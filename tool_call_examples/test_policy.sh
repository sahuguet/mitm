#!/usr/bin/env bash


cat tool1.json | opa eval -I -d policy.rego --format raw 'data.pretool.decision' | jq .

cat tool2.json | opa eval -I -d policy.rego --format raw 'data.pretool.decision' | jq .

cat tool3.json | opa eval -I -d policy.rego --format raw 'data.pretool.decision' | jq .
