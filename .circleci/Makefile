# example usage, after https://circleci.com/docs/2.0/local-cli/ :
#
#  make -C .circleci && circleci local execute -c .circleci/config.yml-local --job coverity-auth -e COVERITY_EMAIL=myemailhere -e COVERITY_PROJECT=foo -e COVERITY_TOKEN=XX

config.yml-local: config.yml
	circleci config process $< > $@

