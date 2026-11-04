#!/usr/bin/env bash
# Generates IntelliJ run configurations (.run/*.run.xml, shared via git) from the env files in example/env:
# one "quarkus:dev (<scenario>)" Maven configuration per env file with the file's variables as environment,
# plus two shell configurations for the demo stack. Re-run after changing an env file.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .run
xml() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' <<<"$1"; }

for f in example/env/*.env; do
  name=$(basename "$f" .env)
  out=".run/dev-$name.run.xml"
  {
    echo '<component name="ProjectRunConfigurationManager">'
    echo "  <configuration default=\"false\" name=\"quarkus:dev ($name)\" type=\"MavenRunConfiguration\" factoryName=\"Maven\">"
    echo '    <MavenSettings>'
    echo '      <option name="myGeneralSettings" />'
    echo '      <option name="myRunnerSettings">'
    echo '        <MavenRunnerSettings>'
    echo '          <option name="delegateBuildToMaven" value="false" />'
    echo '          <option name="environmentProperties">'
    echo '            <map>'
    while IFS= read -r line || [ -n "$line" ]; do
      [[ "$line" =~ ^[[:space:]]*# || -z "${line// }" ]] && continue
      key=${line%%=*}; value=${line#*=}
      echo "              <entry key=\"$(xml "$key")\" value=\"$(xml "$value")\" />"
    done < "$f"
    echo '            </map>'
    echo '          </option>'
    echo '          <option name="jreName" value="#USE_PROJECT_JDK" />'
    echo '          <option name="mavenProperties"><map /></option>'
    echo '          <option name="passParentEnv" value="true" />'
    echo '          <option name="runMavenInBackground" value="true" />'
    echo '          <option name="skipTests" value="false" />'
    echo '          <option name="vmOptions" value="" />'
    echo '        </MavenRunnerSettings>'
    echo '      </option>'
    echo '      <option name="myRunnerParameters">'
    echo '        <MavenRunnerParameters>'
    echo '          <option name="profiles"><set /></option>'
    echo '          <option name="goals"><list><option value="quarkus:dev" /></list></option>'
    echo '          <option name="pomFileName" value="pom.xml" />'
    echo '          <option name="profilesMap"><map /></option>'
    echo '          <option name="resolveToWorkspace" value="false" />'
    echo '          <option name="workingDirPath" value="$PROJECT_DIR$" />'
    echo '        </MavenRunnerParameters>'
    echo '      </option>'
    echo '    </MavenSettings>'
    echo '    <method v="2" />'
    echo '  </configuration>'
    echo '</component>'
  } > "$out"
  echo "wrote $out"
done

shell() { # name, file, script
  cat > ".run/$2.run.xml" <<XML
<component name="ProjectRunConfigurationManager">
  <configuration default="false" name="$1" type="ShConfigurationType">
    <option name="SCRIPT_TEXT" value="$(xml "$3")" />
    <option name="INDEPENDENT_SCRIPT_PATH" value="true" />
    <option name="SCRIPT_PATH" value="" />
    <option name="SCRIPT_OPTIONS" value="" />
    <option name="INDEPENDENT_SCRIPT_WORKING_DIRECTORY" value="true" />
    <option name="SCRIPT_WORKING_DIRECTORY" value="\$PROJECT_DIR\$/example" />
    <option name="INDEPENDENT_INTERPRETER_PATH" value="true" />
    <option name="INTERPRETER_PATH" value="/bin/zsh" />
    <option name="INTERPRETER_OPTIONS" value="" />
    <option name="EXECUTE_IN_TERMINAL" value="true" />
    <option name="EXECUTE_SCRIPT_FILE" value="false" />
    <envs />
    <method v="2" />
  </configuration>
</component>
XML
  echo "wrote .run/$2.run.xml"
}
shell "demo stack: up (Keycloak + Mailpit)" "demo-stack-up" "docker compose up -d && docker compose logs -f keycloak"
shell "demo stack: reset (down -v, re-imports the realm)" "demo-stack-reset" "docker compose down -v && docker compose up -d && docker compose logs -f keycloak"
