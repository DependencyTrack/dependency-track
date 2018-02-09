#!/usr/bin/env bash

cd docs
bundle install
bundle exec jekyll serve
cd ..