#!/bin/sh

YARN=yarn
if which yarn >/dev/null ; then
    YARN=yarn
    yarn config set registry https://registry.npmjs.org
else
    if which npm >/dev/null ; then
        YARN=npm
    else
        echo "No yarn or npm installed."
        exit 1
    fi
fi

cd js_build/js-bindings/tests && ${YARN} install && exec node ./test.js
