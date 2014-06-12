#!/bin/bash

# Set up the directory 'doc/gh-pages' as a git "workdir" that can contain a different branch of the repository.
# Thanks to: http://raxcloud.blogspot.com/2013/02/documenting-python-code-using-sphinx.html
bash /usr/share/doc/git/contrib/workdir/git-new-workdir . doc/gh-pages || /usr/local/share/git-core/contrib/workdir/git-new-workdir . doc/gh-pages

(cd doc/gh-pages && git checkout gh-pages)

# Symlink the Git pre-commit hook into place.
if [ ! -e .git/hooks/pre-commit ] ; then
	ln -s ../../git_hook_pre-commit.sh .git/hooks/pre-commit
fi
