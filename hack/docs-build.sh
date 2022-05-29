#!/usr/bin/env bash

pushd docs >/dev/null
(bundle install --path ./vendor/bundle && bundle exec jekyll build) || true
popd >/dev/null