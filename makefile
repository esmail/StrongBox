SHELL := /bin/bash

doc: doc/gh-pages/ doc/gh-pages/sphinx/

autodoc: .git/hooks/pre-commit doc/gh-pages

virtual_env/: requirements.txt
	virtualenv virtual_env
	source virtual_env/bin/activate && pip install -r requirements.txt

virtual_env/lib/python2.7/site-packages/nose/:
	source virtual_env/bin/activate && pip install -r test_reqs.txt

test: virtual_env/ virtual_env/lib/python2.7/site-packages/nose/
	source virtual_env/bin/activate && nosetests

.git/hooks/pre-commit: git_hook_pre-commit.sh
	# Symlink the Git pre-commit hook into place
	# TODO: Convert this ugly crap to a multi-liner that actually executes.
	if [ ! -e .git/hooks/pre-commit ] ; then ln -s ../../git_hook_pre-commit.sh .git/hooks/pre-commit ; fi

doc/gh-pages/:
	# Set up the directory 'doc/gh-pages' as a git "workdir" that can contain a different branch of the repository.
	# Thanks to: http://raxcloud.blogspot.com/2013/02/documenting-python-code-using-sphinx.html
	bash /usr/share/doc/git/contrib/workdir/git-new-workdir . doc/gh-pages || /usr/local/share/git-core/contrib/workdir/git-new-workdir . doc/gh-pages
	(cd doc/gh-pages && git checkout gh-pages)

doc/source/%.rst: %.py
	source virtual_env/bin/activate && sphinx-apidoc --force --no-toc -o doc/source/ . doc

virtual_env/lib/python2.7/site-packages/sphinx/: virtual_env/
	source virtual_env/bin/activate && pip install sphinx

doc/gh-pages/sphinx/: virtual_env/lib/python2.7/site-packages/sphinx/ doc/source/*.rst doc/source/conf.py
	source virtual_env/bin/activate && cd doc && make html # && make coverage # (Sphinx's coverage builder doesn't seem to actually do anything...)

