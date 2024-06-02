## 環境変数の値の取得方法
それぞれ以下のコマンドでファイルを生成し、ファイルに記録されたテキスト形式の値を環境変数にセットする。
- PRIVATE_KEY
`openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048`
- PUBLIC_KEY
`openssl rsa -pubout -in private.pem -out public.pem`
