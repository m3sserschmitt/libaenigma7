openssl genrsa -out ../build/private.pem 2048
openssl rsa -in ../build/private.pem -outform PEM -pubout -out ../build/public.pem
