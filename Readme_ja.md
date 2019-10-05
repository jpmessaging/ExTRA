# 概要

ExTRA.ps1 は Exchange サーバーの ETW トレースを取得するための関数を含む PowerShell スクリプトです。


# 利用方法

1. ExTRA.ps1 をダウンロードし、ブロックを解除します。

    [ダウンロード](https://github.com/jpmessaging/ExTRA/releases/download/v2019-10-04/ExTRA.ps1)

   1.1. ファイルを右クリックして、プロパティを開きます
   1-2. [全般] タブにて、「このファイルは他のコンピューターから取得したものです。このコンピューターを保護するため、このファイルへのアクセスはブロックされる可能性があります。」というメッセージが表示されている場合には、[許可する] にチェックを入れます。

2. 対象の Exchange サーバー上に ExTRA.ps1 をコピーします。
3. 管理者権限で Exchange 管理シェルを起動します。
4. ドット ソースで ExTRA.ps1 をインポートします。

    ```PowerShell
    . <ExTRA.ps1 へのパス>

    例:
    . c:\temp\ExTRA.ps1
    ```

5. Collect-ExTRA を実行します

    ※ 採取するコンポーネントとタグについてはエンジニアからの案内をご確認ください。

    ```PowerShell
    Collect-ExTRA -Path <出力先フォルダ> -ComponentAndTags <採取するコンポーネントとタグのハッシュテーブル>

    例:
    Collect-ExTRA -Path C:\temp -ComponentAndTags @{'ADProvider'='*';'Data.Storage'='*'}
    ```

6. 正常にトレースが開始されると、`"ExTRA has successfully started. Hit enter to stop ExTRA"` と表示されるので、 事象を再現します。
7. 再現後、コンソールに Enter キーを入力しトレースを停止します。


手順 5 で出力先に指定したフォルダに `"ExTRA_<サーバー名>_<取得日時>.zip"` という名前の ZIP ファイルが作成されます。こちらをお寄せください。