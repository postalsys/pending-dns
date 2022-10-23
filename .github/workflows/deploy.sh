on:
    push:
        branches:
            - master

name: Deploy instance

jobs:
    deploy:
        name: Deploy
        runs-on: ubuntu-latest

        steps:
            - name: Checkout
              uses: actions/checkout@v2

            - name: Install SSH key
              uses: shimataro/ssh-key-action@v2
              with:
                  key: ${{ secrets.SSH_KEY }}
                  known_hosts: ${{ secrets.KNOWN_HOSTS }}

            - name: Deploy to server
              env:
                  TARGET_HOST_01: dns-01.emailengine.app
                  TARGET_HOST_02: dns-02.emailengine.app
                  NODE_ENV: production
                  SERVICE_NAME: pending-dns
              id: deploy
              run: |
                  echo $GITHUB_SHA > commit.txt
                  npm install --production
                  tar czf /tmp/${SERVICE_NAME}.tar.gz --exclude .git .
                  scp /tmp/${SERVICE_NAME}.tar.gz deploy@${TARGET_HOST_01}:
                  scp /tmp/${SERVICE_NAME}.tar.gz deploy@${TARGET_HOST_02}:
                  ssh deploy@$TARGET_HOST_01 "/opt/deploy.sh ${SERVICE_NAME}"
                  ssh deploy@$TARGET_HOST_02 "/opt/deploy.sh ${SERVICE_NAME}"

