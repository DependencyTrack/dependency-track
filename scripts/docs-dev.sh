#!/usr/bin/env bash

pushd docs >/dev/null
(bundle install --path ./vendor/bundle && bundle exec jekyll serve) || true
popd >/dev/null