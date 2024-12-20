## 概要
ExTRA.psm1 は Exchange サーバーの ETW トレースを取得するための関数を含む PowerShell スクリプトです。

[ダウンロード](https://github.com/jpmessaging/ExTRA/releases/download/v2024-12-20/ExTRA.psm1)

SHA256: `74AA42748A41644F80C18134384A69081BF6B07BB296EA1BAAF576F40A325EBF`

`Get-FileHash` コマンドでファイル ハッシュを取得できます:

  ```PowerShell
  Get-FileHash <.psm1 ファイルのパス> -Algorithm SHA256
  ```

## 利用方法


1. ExTRA.psm1 ファイルを右クリックして、プロパティを開きます

   [全般] タブにて、`このファイルは他のコンピューターから取得したものです。このコンピューターを保護するため、このファイルへのアクセスはブロックされる可能性があります。` というメッセージが表示されている場合には、`許可する` にチェックを入れます。

2. 対象の Exchange サーバー上に ExTRA.psm1 をコピーします。
3. 管理者権限で Exchange 管理シェルを起動します。
4. ExTRA.psm1 をインポートします。

    ```PowerShell
    Import-Module <ExTRA.psm1 へのパス> -DisableNameChecking
    ```

    例:
    ```PowerShell
    Import-Module c:\temp\ExTRA.psm1 -DisableNameChecking
    ```

5. Collect-ExTRA を実行します

    ※ 採取するコンポーネント (とタグ) についてはエンジニアからの案内をご確認ください。

    ```
    Collect-ExTRA -Path <出力先フォルダ> -Components <採取するコンポーネント名の配列> -ComponentAndTags <採取するコンポーネントとタグのハッシュテーブル>
    ```

    例:
    ```
    Collect-ExTRA -Path C:\temp -Components ADProvider, Data.Storage -ComponentAndTags @{'SystemLogging'= 'SystemNet,SystemNetSocket'}
    ```

    ⚠️ `Components` で指定されたものは、すべてのタグについてトレースが有効化されます。`ComponentAndTags` で指定されたものは、明示的に指定されたタグについてのみ有効化されます。

6. 正常にトレースが開始されると、`ExTRA has successfully started. Press enter to stop:` と表示されるので、 事象を再現します。
7. 再現後、コンソールに Enter キーを入力しトレースを停止します。


手順 5 で出力先に指定したフォルダに `"ExTRA_<サーバー名>_<取得日時>.zip"` という名前の ZIP ファイルが作成されます。こちらをお寄せください。

## ライセンス
Copyright (c) 2020 Ryusuke Fujita

This software is released under the MIT License.  
http://opensource.org/licenses/mit-license.php

以下に定める条件に従い、本ソフトウェアおよび関連文書のファイル（以下「ソフトウェア」）の複製を取得するすべての人に対し、ソフトウェアを無制限に扱うことを無償で許可します。これには、ソフトウェアの複製を使用、複写、変更、結合、掲載、頒布、サブライセンス、および/または販売する権利、およびソフトウェアを提供する相手に同じことを許可する権利も無制限に含まれます。

上記の著作権表示および本許諾表示を、ソフトウェアのすべての複製または重要な部分に記載するものとします。

ソフトウェアは「現状のまま」で、明示であるか暗黙であるかを問わず、何らの保証もなく提供されます。ここでいう保証とは、商品性、特定の目的への適合性、および権利非侵害についての保証も含みますが、それに限定されるものではありません。 作者または著作権者は、契約行為、不法行為、またはそれ以外であろうと、ソフトウェアに起因または関連し、あるいはソフトウェアの使用またはその他の扱いによって生じる一切の請求、損害、その他の義務について何らの責任も負わないものとします。