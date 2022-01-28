#!/bin/sh

# Copyright 2021 Verisign, Inc.

RED=''
GRN=''
YEL=''
NC='' # No Color

if test $# -eq 0 ; then
	VERIFIERS=$(ls verifiers/*.sh)
else
	VERIFIERS=$*
fi

for VSH in $VERIFIERS ; do
	V=$(basename "$VSH")
	NPASS=0
	NFAIL=0
	VL=logs/$(basename "$V" .sh).log
	cp /dev/null "$VL"
	for Z in $(cd zones || exit ; ls) ; do
		origin=''
		zonefile=''
		expected_result=''
		try_canonical=''
		# shellcheck source=zones/01-sha384-simple/config
		. "zones/$Z/config"
		if test "$expected_result" = "fail" ; then
                	echo "'fail' should be 'failure' in zones/$Z/config"
			exit 1
		fi
		echo ""					>> "$VL"
		echo "===== Verify $Z with $V ===="	>> "$VL"
		printf "%s verifying %s: " "$V" "$Z"
		sh "verifiers/$V" "$origin" "zones/$Z/$zonefile" >> "$VL" 2>&1
		result=$?
		RETRIES=''
		if test '(' $result -eq 1 -a "$expected_result" = "success" ')' -o '(' $result -eq 0 -a "$expected_result" = "failure" ')' ; then
			if test "$try_canonical" = "yes" ; then
				echo "Retry after canonicalizing with named-checkzone" >> "$VL"
				TF=$(mktemp)
				trap 'rm -f $TF' EXIT
				named-checkzone -i none -o "$TF" "$origin" "zones/$Z/$zonefile" >> "$VL" 2>&1
				sh "verifiers/$V" "$origin" "$TF" >> "$VL" 2>&1
				result=$?
				rm -f "$TF"
				RETRIES=" ${YEL}(tried named-checkzone)"
			fi
		fi
		if test $result -eq 0 -a "$expected_result" = "success" ; then
			echo "${GRN}Success as expected${RETRIES}${NC}"
			echo "OK: Success as expected" >> "$VL"
			NPASS=$((NPASS + 1))
		elif test $result -ne 0 -a "$expected_result" = "failure" ; then
			echo "${GRN}Failed as expected${RETRIES}${NC}"
			echo "OK: Failed as expected" >> "$VL"
			NPASS=$((NPASS + 1))
		else 
			echo "${RED}Expected $expected_result but return code was $result${RETRIES}${NC}"
			echo "ERROR: Expected $expected_result but return code was $result" >> "$VL"
			NFAIL=$((NFAIL + 1))
		fi
	done
	echo "Tests Passed: $NPASS"
	echo "Tests Failed: $NFAIL"
	echo "" >> "$VL"
	echo "===========================" >> "$VL"
	echo "Tests Passed: $NPASS" >> "$VL"
	echo "Tests Failed: $NFAIL" >> "$VL"
done
