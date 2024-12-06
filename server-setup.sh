source env/bin/activate
cd NIpsIds/

../env/bin/daphne -b 0.0.0.0 -p 8080 NIpsIds.asgi:application