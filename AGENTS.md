# Agent Guidance

## Running Tests

Always tee test output to a file rather than piping directly into `tail`. This keeps the full output accessible for inspection without truncation.

```bash
# ✅ GOOD — full output preserved, can be grepped/tailed afterwards
mvn test -Dtest="MyTest" 2>&1 | tee /tmp/test-output.txt
grep -E "Tests run|FAIL|ERROR" /tmp/test-output.txt
tail -50 /tmp/test-output.txt

# ❌ BAD — output is lost if the tail window is too small
mvn test -Dtest="MyTest" 2>&1 | tail -60
```
