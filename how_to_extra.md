## ExTRA トレース情報の採取手順 (Exchange 2010)

下記の手順は、現象発生時に実施して採取くださいますようお願いいたします。

1. コマンド プロンプトから extra と実行します。

    初めて実行する際には [更新とカスタマー フィードバック] ページが表示されます。以下の選択をして、「[ようこそ] ページに移動する」をクリックします。

    ```
    - 起動時に更新プログラムを確認しない
    - 現時点では、プログラムに参加しない
    ```

2. "ようこそ" ページにて [タスクを選択する] をクリックします。
3. [トレース制御] をクリックします。

    ※ 以下の警告ダイアログ ボックスが表示された場合には [OK] をクリックします。
    ```
    このサーバーには、トレースを解釈するために必要なモジュールがありません。認定された Exchange サポート エンジニアの直接の監督下で実行する場合にのみ続行してください
    ```

4. [トレース ファイルを構成する] ページにて以下の設定を確認して [トレース タグを手動で選択する] をクリックします。

    | 設定項目                                     | 値                                                                    |
    | -------------------------------------------- | --------------------------------------------------------------------- |
    | トレース ファイルの場所を選択してください    | トレースファイルの保存先ディレクトリ                                  |
    | トレース ファイルの名前を選択してください    | トレース ファイル名 (***.etl)                                         |
    | トレースの最大サイズ (MB) を入力してください | 1024 (既定では 100 MB)                                                |
    | トレース ファイルの動作を選択してください    | [トレース ファイルの最大サイズに達すると、新しいファイルを作成します] |
    | 次の間トレースを実行する                     | オフ                                                                  |
    | 必要なトレースの種類を選択してください       | [トレースを手動で選択する]                                            |

5. "トレースの種類" のチェック ボックスをすべてオンにします。
6. "トレースするコンポーネント" にて対象のコンポーネントにチェックボックスをオンにします。

    ※ エンジニアより案内された内容を選択ください。

7. [トレースを開始する] をクリックし "トレースを制御する" 画面へ遷移するまで待ちます。
8. 現象を再現します。
9. [今すぐトレースを停止する] をクリックします。
10. ウィンドウをクローズします。
11. C: ドライブ直下に "EnabledTraces.Config" というファイルが作成されているため、これを削除ください。
12. プロセス ID 等を確認するために当該サーバー上で PowerShell にて以下を実行します

    ```PowerShell
    Get-WmiObject win32_process | Export-Clixml <出力先ファイル.xml>

    例: Get-WmiObject win32_process | Export-Clixml c:\tmp\processes.xml
    ```

手順 4 で指定したファイル (*.etl) と手順 12 で出力した XML ファイルをお寄せください。

---

## ExTRA トレース情報の採取手順 (Exchange 2013 以降)

ExTRA は既定ではインストールされていないため、エンジニアより提供されたものを対象のサーバーにインストールします。既定では C:\Program Files\Exchange ExTRA\ にインストールされます。

1. ExTRA を起動します。

    初めて実行する際には [Updates and Customer Feedback] ページが表示されます。以下の選択をして、 [Go to the Welcome screen] をクリックします。

    ```
    - Do not check for updates on startup
    - I don't want to join the program at this time
    ```

2. [Select a task] をクリックします。
3. [Trace Control] をクリックします。

    ※ 以下の警告ダイアログ ボックスが表示された場合は [OK] をクリックします。

    ```
    This server does not have the module needed for interpreting traces.  Proceed only if this is being done under the direct supervision of a qualified Exchange support engineer.
    ```

4. [Configure Trace File] ページにて以下の設定を確認して [Set manual trace tags] をクリックします。

    | 設定項目                          | 値                                                                              |
    | --------------------------------- | ------------------------------------------------------------------------------- |
    | Select trace file location        | トレースファイルの保存先ディレクトリ (既定では C:\Program Files\Exchange ExTRA) |
    | Select trace file name            | トレース ファイル名 (***.etl)                                                   |
    | Enter max trace file size (MB)    | 1024 (既定では 100 MB)                                                          |
    | Select trace file behavior        | [Create a new file when max trace file size is reached]                         |
    | Run traces for                    | オフ                                                                            |
    | Select the type of tracing needed | Select trace tags manually                                                      |


5. "Trace Types" の項目を全てオンにします。
6. "Components to Trace" と "Trace Tags" を設定します。

    ※ エンジニアより案内された内容を選択ください。

7. [Start Tracing] をクリックし、"Trace Control" 画面へ遷移するまで待ちます。
8. 現象を再現します。
9. [Stop tracing now] をクリックします。
10. ウィンドウをクローズします。
11. C: ドライブ直下に "EnabledTraces.Config" というファイルが作成されているため、これを削除ください。
12. プロセス ID 等を確認するために当該サーバー上で PowerShell にて以下を実行します

    ```PowerShell
    Get-WmiObject win32_process | Export-Clixml <出力先ファイル.xml>

    例: Get-WmiObject win32_process | Export-Clixml c:\tmp\processes.xml
    ```

手順 4 で指定したファイル (*.etl) と手順 12 で出力した XML ファイルをお寄せください。
