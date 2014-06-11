#!/bin/bash

echo "Automatically generating and pushing documentation."

# First make sure the documentation is up to date with the remote.
(cd doc/gh-pages && git pull origin gh-pages)

# Locally regenerate the documentation (if outdated).
make doc

# Push any changes to the remote.
cd doc/gh-pages
git add --all
git commit --no-verify -m "Automatic documentation update by pre-commit hook."
git push origin gh-pages

echo "Automatic documentation sync complete."
