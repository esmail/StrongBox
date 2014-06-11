#!/bin/bash

# Set up the directory 'doc/gh-pages' as a git "workdir" that contains the "gh-pages" (used to generate github.io pages)  branch of the repository.
bash /usr/share/doc/git/contrib/workdir/git-new-workdir . doc/gh-pages || /usr/local/share/git-core/contrib/workdir/git-new-workdir . doc/gh-pages
(cd doc/gh-pages && git checkout gh-pages)

# Symlink the Git pre-commit hook into place.
ln -s ../../git_hook_pre-commit.sh .git/hooks/pre-commit
