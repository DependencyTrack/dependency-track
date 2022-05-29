#!/usr/bin/env bash

pushd docs >/dev/null
(bundle install && bundle exec jekyll build) || true
popd >/dev/null