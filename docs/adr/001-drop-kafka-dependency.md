| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2025-01-07 | [@nscuro](https://github.com/nscuro) |

## Context

### How Kafka is currently used

As of hyades version 0.6.0, Kafka is used for the following purposes:

* **Notification dispatching**. Each notification type has its own Kafka topic. The `notification-publisher` service
  is responsible for consuming from those topics, and publishing notifications based on the configured rules,
  i.e. sending Slack messages or Webhooks. Because Kafka does not delete messages after consumption, notifications
  can be consumed by multiple clients, and replayed if necessary. Given a consistent message key, Kafka can further
  guarantee message ordering.
* **Vulnerability mirroring**. Vulnerability records downloaded from the NVD and other sources are not immediately
  written to the database. Instead, they are sent to a [compacted Kafka topic], from where they are consumed and ingested.
  Kafka acts as a firehose that allows ingestion to be performed at a steady rate, without overloading the database.
* **Vulnerability analysis**. The API server publishes a record for each to-be-analyzed component to Kafka.
  The `vulnerability-analyzer` service consumes from this topic, scans each component with all configured scanners,
  and publishes the results to a separate Kafka topic. The results topic is consumed by the API server,
  which is responsible for ingesting them into the database. Analysis makes heavy use of stream processing techniques
  to improve performance. The full process is documented [here](https://github.com/DependencyTrack/hyades/blob/8f1dd4cb4e02c8b4b646217ddd006ef81490cdec/vulnerability-analyzer/README.md#how-it-works).
* **Repository metadata analysis**. Similar to vulnerability analysis, but for component metadata such as latest
  available versions, publish timestamps, and hashes. The process is documented [here](https://github.com/DependencyTrack/hyades/tree/8f1dd4cb4e02c8b4b646217ddd006ef81490cdec/repository-meta-analyzer#how-it-works).

The Kafka ecosystem is huge, and there exist many managed offerings for it. Over the recent years, many more
projects and products were released that implement the Kafka protocol, giving users more choice.
Operating Kafka has gotten easier, both due to the many new implementations, and because Kafka has dropped
the previously mandatory ZooKeeper dependency.

Message throughput is fantastic. Durability and ordering guarantees are great.

### Issues and limitations

* **Retries**. Kafka does not yet support ACKs or NACKs of individual messages. It works with log offsets,
  making it difficult to implement fine-grained retry mechanisms for individual failed messages,
  without complex client-side solutions. Hyades implements retries using [Kafka Streams state stores],
  or by leveraging [Confluent Parallel Consumer]. With [KIP-932], native ACKs of individual messages are on the horizon.
* **Prioritization**. Kafka is an append-only log, and as such does not support prioritization of messages.
  Prioritization is required to ensure that actions triggered by users or clients take precedence over scheduled ones.
  [Implementing prioritization on top of Kafka primitives](https://www.confluent.io/blog/prioritize-messages-in-kafka/)
  is complex and inflexible. [KIP-932] does not cover priorities. The lack of prioritization can *partly* be compensated
  by ensuring high throughput of the system, which Kafka *does* support. But it's not a sustainable solution.
* **Message sizes**. Kafka has a default message size limit of `1 MiB`. We observed notifications and vulnerability
  analysis results growing larger than `1 MiB`, even when compressed. The size limit can be increased on a per-topic basis,
  but it comes with a performance penalty. We further found that some organizations disallow increasing size limits
  entirely to limit impact on other teams sharing the same brokers.
* **End-to-end observability**. Tracking message flow and workflow progress across multiple topics and services
  requires dedicated monitoring for logs, metrics, and traces. This raises the barrier to entry for operating
  Dependency-Track clusters, and complicates debugging of issues and development. Relying solely on a PubSub broker like
  Kafka or DT v4's internal message bus promotes [choreography] over [orchestration]. Choreography makes processes
  increasingly hard to understand and follow. The initial [workflow state tracking] implementation attempted to lessen
  the pain, but the logic being scattered across all choreography participants is not helpful.
* **Spotty support for advanced Kafka features**. Kafka comes with advanced features like transactions, compacted topics,
  and more. We found that support for these is very spotty across alternative implementations (in particular transactions).
  Further, we received feedback that organizations that operate shared Kafka clusters may prohibit usage of compacted
  topics. With only bare-bones features left available, the argument for Kafka becomes a lot less compelling.
* **Topic management**. Partitions are what enables parallelism for Kafka consumers. The number of partitions must
  be decided before topics are created. Increasing partitions later is possible, decreasing is not. Adding partitions
  impacts ordering guarantees and can be tricky to coordinate. In order to leverage stream processing techniques,
  some topics must be [co-partitioned](https://www.confluent.io/blog/co-partitioning-in-kafka-streams/). 
  Generic tooling around topic management, comparable to database migration tooling, is severely lacking,
  making it hard to maintain for a diverse user base. Vendor-specific tooling is available,
  such as [Strimzi's topic operator](https://strimzi.io/docs/operators/latest/overview#overview-concepts-topic-operator-str).
* **Community support**. Running an additional piece of infrastructure ourselves is one thing. Supporting a whole
  community in doing that correctly and efficiently is another. Unfortunately there is no single deployment
  or configuration that works for everyone. We don't have dedicated support staff and need to be pragmatic about
  what we can realistically support. Requiring Kafka doesn't help.

In summary, *Kafka on its own provides not enough benefit for us to justify its usage*.

We hoped it would help in more areas, but ended up realizing that working around these issues required even more
additional overhead and infrastructure to address. Which is not sustainable, given we already spent [innovation tokens]
on Kafka itself, and have limited team capacities.

### Possible Solutions

#### A: Replace Kafka for another message broker

We could replace Kafka with another, more lightweight broker, like [ActiveMQ], [RabbitMQ], [NATS], or [Redis].

[ActiveMQ] and [RabbitMQ] support [AMQP] and [JMS] as common messaging protocols.
Managed offerings are widely available, both for these specific brokers, and alternative [AMQP] implementations.

[NATS] is capable to cater to the widest range of use cases, but managed offerings are mainly limited to
one vendor ([Synadia]). Realistically, users would need to maintain their own clusters.
[NATS JetStream] can provide Kafka-like semantics, but also work queues, key-value and object stores.
While its protocols are public and well-documented, there are currently no alternative server implementations. 

[Redis] provides data structures for classic queues (i.e. lists) and priority queues (i.e. sorted sets).
It can act as publish-subscribe broker, although it only provides at-most-once delivery guarantees there.

*Pro*:

1. [AMQP]-compatible brokers come with support for retries and prioritization built-in.
2. [NATS] could also be used as blob storage.
3. [Redis] could also be used for caching.

*Con*:

1. Still requires an additional dependency.
2. Still inherits many of the issues we have with Kafka (i.e. topic / queue management, e2e observability).
3. We don't have expertise in configuring and operating any of these.
4. Fully managed offerings are more scarce, especially [NATS].
5. Following a license change in 2024, the [Redis] ecosystem has become fragmented. [Redis] itself is no longer
   permissively licensed. Forks like [ValKey] exist, but the whole situation is concerning.

#### B: Use an in-memory data grid

In-memory data grids (IMDGs) are a popular option for various use cases in the JVM ecosystem,
including messaging. Prominent solutions in this space include [Hazelcast], [Ignite], and [Infinispan].

IMDGs could further be combined with frameworks such as Eclipse [Vert.x], which use them for clustering.

*Pro*:

1. Could also be used for caching.

*Con*:

1. Most IMDGs still require a central server and are thus not necessarily simpler than a normal message broker.
2. No managed offering in any major cloud(?).
3. We only have very limited experience in configuring and operating any of these.
4. Except Hazelcast, only very limited support for advanced data structures like priority queues.
5. Upgrades are tricky to coordinate and require downtime. Rolling upgrades are a paid feature in Hazelcast.

#### C: Just use Postgres

We already decided to focus entirely on Postgres for our database. We dropped support for H2, MSSQL, and MySQL
as a result. This decision opens up a lot more possibilities when it comes to other parts of the stack.

Solutions like [JobRunr], [Hatchet], [Oban], [pgmq], [River], and [Solid Queue] demonstrate that building
queues or queue-like systems on a RDBMSes *and Postgres specifically* is viable.

Running such workloads on a database does not necessarily mean that the database must be shared
with the core application. It *can* be done for smaller deployments to keep complexity low,
but larger deployments can simply leverage a separate database.

Both architecture and operations are simpler, even if more database servers were to be involved.

Database migrations are well understood, easy to test and to automate. With Liquibase, we already have
great tooling in our stack.

Organizations that are able to provision and support a Postgres database for the core application will
also have an easier time to provision more instances if needed, versus having to procure another technology altogether.

Postgres is also a lot more common than any of the message brokers or IMDGs.

Performance-wise, messaging and queueing is not our main bottleneck. Since all asynchronous operations involve
access to a database or external service anyway, raw message throughput is not a primary performance driver for us.

Impact on database performance can be reduced by sizing units of work a little bigger. For example, processing
all components of a project in a single task, rather than each component individually. Fewer writes and fewer
transactions lead to more headroom.

*Pro*:

1. Drastically simplified tech stack. Easier to develop with and to support.
2. We already have expertise in configuration and operation.
3. Abundance of managed offerings across wide range of vendors.
4. Retries, priorities, observability are easier to implement with a strongly consistent SQL database.
5. Migrations are simpler, we already have tooling for it.
6. More flexible: If we have special needs for queueing, we can just build it ourselves,
   rather than adopting yet another technology, or implementing more workarounds.

*Con*:

1. Will not scale as far as Kafka or other dedicated brokers could.
2. We're binding ourselves more to one specific technology.

## Decision

We propose to follow solution **C**. Go all-in on Postgres.

TODO: Update with final decision.

## Consequences

* Functionalities that currently rely on Kafka will need to be re-architected for Postgres.
* Since we already have a few adopters of hyades, the transition will need to be gradual.
* We need a Kafka [notification publisher] to ensure that users relying on this functionality are not cut off.


[ActiveMQ]: https://activemq.apache.org/
[AMQP]: https://www.amqp.org/
[compacted Kafka topic]: https://docs.confluent.io/kafka/design/log_compaction.html
[choreography]: https://microservices.io/patterns/data/saga.html#example-choreography-based-saga
[Confluent Parallel Consumer]: https://github.com/confluentinc/parallel-consumer
[Hatchet]: https://hatchet.run/
[Hazelcast]: https://hazelcast.com/
[JMS]: https://en.wikipedia.org/wiki/Jakarta_Messaging
[JobRunr]: https://www.jobrunr.io/en/
[Ignite]: https://ignite.apache.org/use-cases/in-memory-data-grid.html
[Infinispan]: https://infinispan.org/
[innovation tokens]: https://boringtechnology.club/#17
[Kafka Streams state stores]: https://kafka.apache.org/39/documentation/streams/core-concepts#streams_state
[KIP-932]: https://cwiki.apache.org/confluence/display/KAFKA/KIP-932%3A+Queues+for+Kafka
[NATS]: https://nats.io/
[NATS JetStream]: https://docs.nats.io/nats-concepts/jetstream
[notification publisher]: https://github.com/DependencyTrack/hyades/blob/main/notification-publisher/src/main/java/org/dependencytrack/notification/publisher/Publisher.java
[Oban]: https://getoban.pro/
[orchestration]: https://microservices.io/patterns/data/saga.html#example-orchestration-based-saga
[pgmq]: https://github.com/tembo-io/pgmq
[RabbitMQ]: https://www.rabbitmq.com/
[Redis]: https://redis.io/
[River]: https://riverqueue.com/
[Solid Queue]: https://github.com/rails/solid_queue
[Synadia]: https://www.synadia.com/
[ValKey]: https://valkey.io/
[Vert.x]: https://vertx.io/
[workflow state tracking]: ../design/workflow-state-tracking.md