#!/usr/bin/env bash

set -eo pipefail

_date_cmd=$(command -v date)
if [[ $(uname -s | tr '[:upper:]' '[:lower:]') =~ darwin ]]; then
	_date_cmd=$(command -v gdate)
	if [[ -z ${_date_cmd} ]]; then
		if date '+%s%3N' &>/dev/null; then
			_date_cmd=$(command -v date)
		else
			printf '[FAIL]\t\t gdate not found, please run `brew install coreutils` and try again\n'
			exit 2
		fi
	fi
fi

sanity_usage() {
	_help=$'
Usage:
\t-h\tDisplay this help message.

Options:
\t-c <count>\tTest count (default 5)
\t-K\tEnable TLS certificate checking in requests

Examples:
\t _SELF_ -c 20
\t _SELF_ -c 10 9.122.123.146
'
	column -t -s $'\t' <<<"${_help}" | sed "s|_SELF_|${0}|g"
}

declare -x NO_CHK_CERT="-k"

parse_options() {
	count=5
	while getopts ":hKc:" opt; do
		case ${opt} in
			h)
				sanity_usage
				exit 0
				;;
			K)
				NO_CHK_CERT=""
				;;
			c)
				count="${OPTARG}"
				;;
			*)
				sanity_usage
				exit 127
				;;
		esac
	done
	shift $((OPTIND - 1))
	SSM_API="${1}"
	if [[ -z ${SSM_API} ]]; then
		SSM_API="localhost"
	fi
}

_timestamp() {
	if [[ -n ${1} ]]; then
		printf '(%d ms)' $(($(${_date_cmd} '+%s%3N') - "${1}"))
	else
		printf '(%s)' "$(date -u '+%FT%TZ')"
	fi
}

test_health() {
	local _start=$(${_date_cmd} '+%s%3N')
	local cmd="curl ${CURL_OPTS} -o ${TEMP_OUTFILE} -w '%{http_code}\n' -X GET http://${SSM_API}:8080/healthcheck ${SSM_HEADERS} 2>${TEMP_OUTFILE}"
	local http_code="$(eval "${cmd}")"
	if [[ ${http_code} == "200" ]]; then
		printf '[OK:%d]%s\thealth check was successful!\n' "${http_code}" "$(_timestamp ${_start})"
	else
		printf '[FAIL:%d]%s\thealth check failed :-(\n%s\n' "${http_code}" "$(_timestamp ${_start})" "$(<${TEMP_OUTFILE})"
		exit 1
	fi
}


test_wrap_unwrap() {
	local _start=$(${_date_cmd} '+%s%3N')
	
    root_key="$(openssl rand 32 | base64)"

	#Wrap the secret
	local cmd="curl ${CURL_OPTS} -o ${TEMP_OUTFILE} -w '%{http_code}\n' -X GET http://${SSM_API}:8080/wrap ${SSM_HEADERS} --data '{\"key\":\"$root_key\"}' 2>${TEMP_OUTFILE}"
	local http_code="$(eval "${cmd}")"
	if [[ ${http_code} == "200" ]]; then
		printf '[OK:%d]%s\tsecret wrap operation was successful!\n' "${http_code}" "$(_timestamp ${_start})"
		ciphertext="$(jq -r '.cipher' "${TEMP_OUTFILE}")"
	else
		printf '[FAIL:%d]%s\tsecret wrap operation failed :-(\n%s\n' "${http_code}" "$(_timestamp ${_start})" "$(<${TEMP_OUTFILE})"
		exit 1
	fi

	#Unwrap the secret
	local _start=$(${_date_cmd} '+%s%3N')
	cmd="curl ${CURL_OPTS} -o ${TEMP_OUTFILE} -w '%{http_code}\n' -X GET http://${SSM_API}:8080/unwrap ${SSM_HEADERS} --data '{\"cipher\":\"$ciphertext\"}' 2>${TEMP_OUTFILE}"
	http_code="$(eval "${cmd}")"
	if [[ ${http_code} == "200" ]]; then
		printf '[OK:%d]%s\tsecret unwrap operation successful.. ' "${http_code}" "$(_timestamp ${_start})"
		if [[ "$(jq -r '.key' "${TEMP_OUTFILE}")" == "$root_key" ]]; then
			printf 'unwrapped secret matches original plaintext!\n'
		else
			printf '\n[FAIL]%s\tunwrapped secret does not match original plaintext :-(\n' "$(_timestamp ${_start})"
			exit 1
		fi
	else
		printf '[FAIL:%d]%s\tsecret unwrap operation failed :-(\n%s\n' "${http_code}" "$(_timestamp ${_start})" "$(<${TEMP_OUTFILE})"
		exit 1
	fi
}

run_sanity() {
	SSM_HEADERS='-H "Prefer: return=minimal" -H "Accept: application/json"'
	CURL_OPTS=''"${NO_CHK_CERT}"' -s --connect-timeout 8 --max-time 20 --retry 4 '"${SSM_HEADERS}"''
	printf '\n'
    test_health
	test_wrap_unwrap
}

parse_options "${@}"
printf '[CONF]\t\ttarget: %s\n' "${SSM_API}"
TEMP_OUTFILE="$(mktemp)"
trap "rm -f ${TEMP_OUTFILE}" EXIT
set -E
trap "cat ${TEMP_OUTFILE}" ERR
for ((i = 0; i < count; i++)); do run_sanity; done
