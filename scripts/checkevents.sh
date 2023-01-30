#!/bin/bash

install -d ./target/eventcheck
for i in many_secrets_discovery   simple_timed_lock  single_secret_discovery 
do
   cat ./target/ink/$i/$i.contract  | jq '{"V3"}[]."spec"."events"' > ./target/eventcheck/$i.json
   diff ./golden/$i.json ./target/eventcheck/$i.json >/dev/null || echo '*** ERROR in '$i/events.json Definition changed
done