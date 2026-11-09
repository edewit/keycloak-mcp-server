#!/bin/sh
# Starts keycloak-mcp-server from this distribution.
#
#   bin/kcmcp.sh start                                     conf/kcmcp.conf
#   bin/kcmcp.sh start-dev                                 the same, in development mode: profile local, insecure
#                                                          settings are warned about instead of refused, Keycloak at
#                                                          http://localhost:8080 unless a system is configured
#   bin/kcmcp.sh start --config conf/read-only.conf          a copy of a conf/scenarios/*.conf.example template
#   bin/kcmcp.sh start --config conf/systems/              every *.conf file in it, e.g. one per Keycloak system
#   bin/kcmcp.sh start --kc-mcp.systems.default.url=https://sso.example.com --quarkus.http.port=8082
#   bin/kcmcp.sh start --debug 5005
#   bin/kcmcp.sh start --clean-env                         ignore KC_MCP_* and QUARKUS_* variables of the shell
#   bin/kcmcp.sh --version | --help
#
# Any --name=value becomes the configuration property "name"; environment variables (KC_MCP_SYSTEMS_DEFAULT_URL=...) work as well and
# override the configuration files, so the script lists the ones it inherits from the shell.
# JAVA_HOME or JAVA pick the JVM (Java 21 or newer); JAVA_OPTS replaces the default JVM options, JAVA_OPTS_APPEND
# adds to them. KCMCP_DEBUG=true, KCMCP_DEBUG_PORT and KCMCP_DEBUG_SUSPEND enable remote debugging.

case "$(uname)" in
    CYGWIN*) IS_CYGWIN="true"; RESOLVED_NAME="$(readlink -f "$(cygpath "$0")")" ;;
    Darwin*) RESOLVED_NAME="$(readlink "$0")" ;;
    *)       RESOLVED_NAME="$(readlink -f "$0")" ;;
esac
RESOLVED_NAME="${RESOLVED_NAME:-"$0"}"
BIN_DIR="$(cd "$(dirname "$RESOLVED_NAME")" && pwd)"
KCMCP_HOME="$(cd "$BIN_DIR/.." && pwd)"

abs_path() {
    if [ -z "$IS_CYGWIN" ]; then echo "$1"; else cygpath -w "$1"; fi
}

# a --config argument, a file or a directory of *.conf files: absolute, relative to the current directory, or
# relative to the distribution
conf_file() {
    case "$1" in
        /*) echo "$1" ;;
        *)
            if [ -e "$1" ]; then echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
            elif [ -e "$KCMCP_HOME/$1" ]; then echo "$KCMCP_HOME/$1"
            else echo "$1"
            fi
            ;;
    esac
}

usage() {
    sed -n '2,17p' "$RESOLVED_NAME" | sed 's/^# \{0,1\}//'
}

version() {
    cat "$KCMCP_HOME/version.txt" 2>/dev/null || echo "unknown"
}

esceval() {
    printf '%s\n' "$1" | sed "s/'/'\\\\''/g; 1 s/^/'/; $ s/$/'/"
}

DEBUG_MODE="${KCMCP_DEBUG:-false}"
DEBUG_ADDRESS="${KCMCP_DEBUG_PORT:-5005}"
DEBUG_SUSPEND="${KCMCP_DEBUG_SUSPEND:-n}"
CONFIG_FILES="$KCMCP_HOME/conf/kcmcp.conf"
SERVER_OPTS=""
COMMAND=""
CLEAN_ENV=false

while [ "$#" -gt 0 ]; do
    case "$1" in
        start) COMMAND=start ;;
        start-dev) COMMAND=start-dev ;;
        -h|--help) usage; exit 0 ;;
        -v|--version) version; exit 0 ;;
        --debug)
            DEBUG_MODE=true
            if echo "$2" | grep -Eq '^[0-9]+$'; then DEBUG_ADDRESS="$2"; shift; fi
            ;;
        --clean-env) CLEAN_ENV=true ;;
        --config=*) CONFIG_FILES="$CONFIG_FILES
$(conf_file "${1#--config=}")" ;;
        --config)
            [ -n "$2" ] || { echo "--config needs a file" >&2; exit 2; }
            CONFIG_FILES="$CONFIG_FILES
$(conf_file "$2")"; shift
            ;;
        -D*) SERVER_OPTS="$SERVER_OPTS $(esceval "$1")" ;;
        --*=*)
            NAME="${1#--}"; NAME="${NAME%%=*}"; VALUE="${1#*=}"
            SERVER_OPTS="$SERVER_OPTS $(esceval "-D$NAME=$VALUE")"
            ;;
        *) echo "unknown argument: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done

if [ -z "$COMMAND" ]; then
    usage; exit 2
fi

# configuration inherited from the shell: it overrides the files, which surprises after `source examples/.../x.env`
INHERITED="$(env | grep -oE '^(KC_MCP|QUARKUS)_[A-Z0-9_]+=' | tr -d '=' | sort | tr '\n' ' ')"
if [ -n "$INHERITED" ]; then
    if [ "$CLEAN_ENV" = "true" ]; then
        for v in $INHERITED; do unset "$v"; done
        echo "ignoring the environment's $INHERITED" >&2
    else
        echo "note: the environment sets $INHERITED(these override the configuration files; --clean-env ignores them)" >&2
    fi
fi

# one file per line, so paths with spaces survive; the server reads the list from kc-mcp.config-files
CONFIG_LIST=""
while IFS= read -r f; do
    [ -n "$f" ] || continue
    if [ ! -e "$f" ]; then
        echo "configuration file not found: $f" >&2; exit 2
    fi
    CONFIG_LIST="$CONFIG_LIST${CONFIG_LIST:+,}$(abs_path "$f")"
done <<EOF
$CONFIG_FILES
EOF

if [ -z "$JAVA" ]; then
    if [ -n "$JAVA_HOME" ]; then JAVA="$JAVA_HOME/bin/java"; else JAVA="java"; fi
fi
JAVA_MAJOR="$("$JAVA" -version 2>&1 | sed -n 's/.*version "\([0-9]*\).*/\1/p' | head -1)"
if [ -n "$JAVA_MAJOR" ] && [ "$JAVA_MAJOR" -lt 21 ]; then
    echo "keycloak-mcp-server needs Java 21 or newer; $JAVA is $JAVA_MAJOR. Set JAVA_HOME." >&2; exit 1
fi

if [ -z "$JAVA_OPTS" ]; then
    JAVA_OPTS="-Xms64m -Xmx512m -XX:+UseG1GC -XX:+ExitOnOutOfMemoryError -Dfile.encoding=UTF-8 -Djava.security.egd=file:/dev/urandom"
fi
if [ -n "$JAVA_OPTS_APPEND" ]; then
    JAVA_OPTS="$JAVA_OPTS $JAVA_OPTS_APPEND"
fi
if [ "$DEBUG_MODE" = "true" ]; then
    JAVA_OPTS="$JAVA_OPTS -agentlib:jdwp=transport=dt_socket,address=$DEBUG_ADDRESS,server=y,suspend=$DEBUG_SUSPEND"
fi

if [ "$COMMAND" = "start-dev" ]; then
    # development mode: the local profile's lenient defaults whatever the files say, startup problems with Keycloak
    # are warnings, and without a configured system the Keycloak of the examples at http://localhost:8080 is assumed;
    # nothing for a server other people reach
    echo "development mode (start-dev): profile local, startup checks warn, Keycloak at http://localhost:8080 unless a system is configured; use 'start' for a shared server" >&2
    SERVER_OPTS="$SERVER_OPTS -Dkc-mcp.profile=local -Dkc-mcp.startup-check=warn -Dkc-mcp.dev-mode=true"
fi

# where this distribution keeps things; the configuration may refer to ${kcmcp.home.dir}
HOME_OPTS="-Dkcmcp.home.dir=$(esceval "$(abs_path "$KCMCP_HOME")")"
HOME_OPTS="$HOME_OPTS -Dkc-mcp.config-files=$(esceval "$CONFIG_LIST")"
HOME_OPTS="$HOME_OPTS -Dkc-mcp.providers-dir=$(esceval "$(abs_path "$KCMCP_HOME/providers")")"
HOME_OPTS="$HOME_OPTS -Dkc-mcp.keys-dir=$(esceval "$(abs_path "$KCMCP_HOME/data/keys")")"
HOME_OPTS="$HOME_OPTS -Djava.util.logging.manager=org.jboss.logmanager.LogManager"

JAR="$(esceval "$(abs_path "$KCMCP_HOME/lib/quarkus-run.jar")")"

if [ "$KCMCP_PRINT_ENV" = "true" ]; then
    echo "Using JAVA: $JAVA"
    echo "Using JAVA_OPTS: $JAVA_OPTS"
    echo "Using SERVER_OPTS: $HOME_OPTS $SERVER_OPTS"
fi

cd "$KCMCP_HOME" || exit 1
eval exec "'$JAVA'" $JAVA_OPTS $HOME_OPTS $SERVER_OPTS -jar "$JAR"
