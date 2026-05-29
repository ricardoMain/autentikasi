#!/bin/bash
BASE="http://localhost:8080/api/auth"

echo "=== Register (skip kalo udah ada) ==="
curl -s -X POST "$BASE/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123","name":"Test User"}' | jq .

echo -e "\n=== Login ==="
LOGIN=$(curl -s -X POST "$BASE/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}')
echo "$LOGIN" | jq .

ACCESS=$(echo "$LOGIN" | jq -r '.data.access_token')
REFRESH=$(echo "$LOGIN" | jq -r '.data.refresh_token')

echo -e "\n=== Profile ==="
curl -s "$BASE/me" -H "Authorization: Bearer $ACCESS" | jq .

echo -e "\n=== Refresh ==="
REFRESHED=$(curl -s -X POST "$BASE/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH\"}")
echo "$REFRESHED" | jq .
NEW_REFRESH=$(echo "$REFRESHED" | jq -r '.data.refresh_token')

echo -e "\n=== Logout ==="
curl -s -X POST "$BASE/logout" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$NEW_REFRESH\"}" | jq .
