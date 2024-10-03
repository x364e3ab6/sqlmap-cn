
<p align="center">
  <h1 align="center">DudeSuite SQLMAP 中文版</h1>
</p>

<p align="center">
<a href="https://www.dudesuite.cn/" target='_blank'><img src="https://img.shields.io/badge/%E5%AE%98%E6%96%B9%E7%BD%91%E7%AB%99-%E7%82%B9%E5%87%BB%E6%89%93%E5%BC%80style=square"></a>
<a href="https://github.com/x364e3ab6/sqlmap-cn/releases/"><img src="https://img.shields.io/github/release/x364e3ab6/sqlmap-cn?label=%E6%9C%80%E6%96%B0%E7%89%88%E6%9C%AC&style=square"></a>
<a href="https://github.com/x364e3ab6/sqlmap-cn/releases"><img src="https://img.shields.io/github/downloads/x364e3ab6/sqlmap-cn/total?label=%E4%B8%8B%E8%BD%BD%E6%AC%A1%E6%95%B0&style=square"></a>
<a href="https://github.com/x364e3ab6/sqlmap-cn/issues"><img src="https://img.shields.io/github/issues-raw/x364e3ab6/sqlmap-cn?label=%E9%97%AE%E9%A2%98%E5%8F%8D%E9%A6%88&style=square"></a>
<a href="https://github.com/x364e3ab6/sqlmap-cn/discussions"><img src="https://img.shields.io/github/stars/x364e3ab6/sqlmap-cn?label=%E7%82%B9%E8%B5%9E%E6%98%9F%E6%98%9F&style=square"></a>
</p>

&emsp;&emsp;sqlmap 是一个开源的渗透测试工具，主要用于检测和利用 SQL 注入漏洞，广泛用于网站安全评估和渗透测试。此项目对sqlmap进行了较为完整的汉化并衍生两个版本，一个是跨平台的Python版本适合在Linux及macOS等跨平台使用，另一个是编译为可执行文件的exe版本可在Windows平台使用并且不依赖Python环境，更加符合中国宝宝的体质。

![1727938761163](https://github.com/user-attachments/assets/2fa3639d-8187-4733-9c0c-e9d630d48c66)

''''
Usage: sqlmap.exe [选项]

Options:
  -h, --help            Show basic help message and exit
  -hh                   显示高级帮助信息并退出
  --version             显示程序版本号并退出
  -v VERBOSE            详细程度: 0-6 (默认 1)

  目标:
    必须提供以下选项之一以定义目标

    -u URL, --url=URL   目标 URL (例如 "http://www.site.com/vuln.php?id=1")
    -d DIRECT           直接数据库连接的连接字符串
    -l LOGFILE          从 Burp 或 WebScarab 代理日志文件中解析目标
    -m BULKFILE         从文本文件中扫描多个目标
    -r REQUESTFILE      从文件中加载 HTTP 请求
    -g GOOGLEDORK       将 Google dork 结果作为目标 URL 处理
    -c CONFIGFILE       从配置 INI 文件加载选项

  请求:
    这些选项可用于指定如何连接到目标 URL

    -A AGENT, --user..  HTTP User-Agent 头值
    -H HEADER, --hea..  额外头部 (例如 "X-Forwarded-For: 127.0.0.1")
    --method=METHOD     强制使用给定的 HTTP 方法 (例如 PUT)
    --data=DATA         通过 POST 发送的数据字符串 (例如 "id=1")
    --param-del=PARA..  用于分割参数值的字符 (例如 &)
    --cookie=COOKIE     HTTP Cookie 头值 (例如 "PHPSESSID=a8d127e..")
    --cookie-del=COO..  用于分割 cookie 值的字符 (例如 ;)
    --live-cookies=L..  用于加载最新值的实时 cookies 文件
    --load-cookies=L..  包含 Netscape/wget 格式的 cookies 的文件
    --drop-set-cookie   忽略响应中的 Set-Cookie 头
    --mobile            通过 HTTP User-Agent 头模拟智能手机
    --random-agent      使用随机选择的 HTTP User-Agent 头值
    --host=HOST         HTTP Host 头值
    --referer=REFERER   HTTP Referer 头值
    --headers=HEADERS   额外头部 (例如 "Accept-Language: fr\nETag: 123")
    --auth-type=AUTH..  HTTP 认证类型 (Basic, Digest, Bearer, ...)
    --auth-cred=AUTH..  HTTP 认证凭据 (name:password)
    --auth-file=AUTH..  HTTP 认证 PEM 证书/私钥文件
    --abort-code=ABO..  在 (有问题的) HTTP 错误代码下中止 (例如 401)
    --ignore-code=IG..  忽略 (有问题的) HTTP 错误代码 (例如 401)
    --ignore-proxy      忽略系统默认的代理设置
    --ignore-redirects  忽略重定向尝试
    --ignore-timeouts   忽略连接超时
    --proxy=PROXY       使用代理连接到目标 URL
    --proxy-cred=PRO..  代理认证凭据 (name:password)
    --proxy-file=PRO..  从文件加载代理列表
    --proxy-freq=PRO..  从给定列表更改代理之间的请求次数
    --tor               使用 Tor 匿名网络
    --tor-port=TORPORT  设置与默认不同的 Tor 代理端口
    --tor-type=TORTYPE  设置 Tor 代理类型 (HTTP, SOCKS4 或 SOCKS5 (默认))
    --check-tor         检查 Tor 是否正确使用
    --delay=DELAY       每个 HTTP 请求之间的延迟（秒）
    --timeout=TIMEOUT   在超时连接之前等待的秒数 (默认 30)
    --retries=RETRIES   连接超时时的重试次数 (默认 3)
    --retry-on=RETRYON  在正则匹配内容时重试请求 (例如 "drop")
    --randomize=RPARAM  随机更改给定参数的值
    --safe-url=SAFEURL  在测试期间频繁访问的 URL 地址
    --safe-post=SAFE..  发送到安全 URL 的 POST 数据
    --safe-req=SAFER..  从文件加载安全 HTTP 请求
    --safe-freq=SAFE..  在访问安全 URL 之间的定期请求
    --skip-urlencode    跳过载荷数据的 URL 编码
    --csrf-token=CSR..  用于保存 anti-CSRF 令牌的参数
    --csrf-url=CSRFURL  用于提取 anti-CSRF 令牌的 URL 地址
    --csrf-method=CS..  在访问 anti-CSRF 令牌页面时使用的 HTTP 方法
    --csrf-data=CSRF..  在访问 anti-CSRF 令牌页面时发送的 POST 数据
    --csrf-retries=C..  提取 anti-CSRF 令牌的重试次数 (默认 0)
    --force-ssl         强制使用 SSL/HTTPS
    --chunked           使用 HTTP 分块传输编码 (POST) 请求
    --hpp               使用 HTTP 参数污染方法
    --eval=EVALCODE     在请求之前评估提供的 Python 代码 (例如 "import
                        hashlib;id2=hashlib.md5(id).hexdigest()")

  优化:
    这些选项可用于优化 sqlmap 的性能

    -o                  打开所有优化开关
    --predict-output    预测常见查询输出
    --keep-alive        使用持久的 HTTP(s) 连接
    --null-connection   在没有实际 HTTP 响应体的情况下获取页面长度
    --threads=THREADS   最大并发 HTTP(s) 请求数 (默认 1)

  注入:
    这些选项可用于指定要测试的参数，提供自定义注入载荷和可选的篡改脚本

    -p TESTPARAMETER    可测试的参数
    --skip=SKIP         跳过给定参数的测试
    --skip-static       跳过看起来不是动态的参数的测试
    --param-exclude=..  正则表达式以排除测试的参数 (例如 "ses")
    --param-filter=P..  按位置选择可测试的参数 (例如 "POST")
    --dbms=DBMS         强制后端数据库管理系统的提供值
    --dbms-cred=DBMS..  数据库管理系统认证凭据 (user:password)
    --os=OS             强制后端数据库管理系统的操作系统提供值
    --invalid-bignum    使用大数字无效化值
    --invalid-logical   使用逻辑运算无效化值
    --invalid-string    使用随机字符串无效化值
    --no-cast           关闭载荷类型转换机制
    --no-escape         关闭字符串转义机制
    --prefix=PREFIX     注入载荷前缀字符串
    --suffix=SUFFIX     注入载荷后缀字符串
    --tamper=TAMPER     使用给定脚本篡改注入数据

  检测:
    这些选项可用于自定义检测阶段

    --level=LEVEL       执行的测试级别 (1-5, 默认 1)
    --risk=RISK         执行的测试风险 (1-3, 默认 1)
    --string=STRING     查询评估为真时匹配的字符串
    --not-string=NOT..  查询评估为假时匹配的字符串
    --regexp=REGEXP     查询评估为真时匹配的正则表达式
    --code=CODE         查询评估为真时匹配的 HTTP 代码
    --smart             仅在有积极启发式的情况下执行彻底测试
    --text-only         仅根据文本内容比较页面
    --titles            仅根据页面标题比较页面

  技术:
    这些选项可用于调整特定 SQL 注入技术的测试

    --technique=TECH..  使用的 SQL 注入技术 (默认 "BEUSTQ")
    --time-sec=TIMESEC  延迟 DBMS 响应的秒数 (默认 5)
    --union-cols=UCOLS  测试 UNION 查询 SQL 注入的列范围
    --union-char=UCHAR  用于强行检测列数的字符
    --union-from=UFROM  在 UNION 查询 SQL 注入的 FROM 部分使用的表
    --union-values=U..  用于 UNION 查询 SQL 注入的列值
    --dns-domain=DNS..  用于 DNS 外泄攻击的域名
    --second-url=SEC..  查找二阶响应的结果页面 URL
    --second-req=SEC..  从文件加载二阶 HTTP 请求

  指纹:
    -f, --fingerprint   执行详尽的数据库管理系统版本指纹

  枚举:
    这些选项可用于枚举后端数据库管理系统信息、结构和表中包含的数据

    -a, --all           检索所有内容
    -b, --banner        检索数据库管理系统横幅
    --current-user      检索数据库管理系统当前用户
    --current-db        检索数据库管理系统当前数据库
    --hostname          检索数据库管理系统服务器主机名
    --is-dba            检测数据库管理系统当前用户是否为 DBA
    --users             枚举数据库管理系统用户
    --passwords         枚举数据库管理系统用户密码哈希值
    --privileges        枚举数据库管理系统用户权限
    --roles             枚举数据库管理系统用户角色
    --dbs               枚举数据库管理系统数据库
    --tables            枚举数据库管理系统数据库表
    --columns           枚举数据库管理系统数据库表列
    --schema            枚举数据库管理系统架构
    --count             检索表的条目数
    --dump              转储数据库管理系统数据库表条目
    --dump-all          转储所有数据库管理系统数据库表条目
    --search            搜索列、表和/或数据库名称
    --comments          在枚举期间检查数据库管理系统注释
    --statements        检索正在数据库管理系统上运行的 SQL 语句
    -D DB               要枚举的数据库管理系统数据库
    -T TBL              要枚举的数据库管理系统数据库表
    -C COL              要枚举的数据库管理系统数据库表列
    -X EXCLUDE          不枚举的数据库管理系统数据库标识符
    -U USER             要枚举的数据库管理系统用户
    --exclude-sysdbs    在枚举表时排除数据库管理系统系统数据库
    --pivot-column=P..  数据透视列名称
    --where=DUMPWHERE   在表转储时使用 WHERE 条件
    --start=LIMITSTART  检索的第一个转储表条目
    --stop=LIMITSTOP    检索的最后一个转储表条目
    --first=FIRSTCHAR   检索的查询输出第一个单词字符
    --last=LASTCHAR     检索的查询输出最后一个单词字符
    --sql-query=SQLQ..  要执行的 SQL 语句
    --sql-shell         提示进行交互式 SQL shell
    --sql-file=SQLFILE  从给定文件中执行 SQL 语句

  暴力破解:
    这些选项可用于运行暴力破解检查

    --common-tables     检查常见表的存在
    --common-columns    检查常见列的存在
    --common-files      检查常见文件的存在

  用户定义函数注入:
    这些选项可用于创建自定义用户定义函数

    --udf-inject        注入自定义用户定义函数
    --shared-lib=SHLIB  共享库的本地路径

  文件系统访问:
    这些选项可用于访问后端数据库管理系统底层文件系统

    --file-read=FILE..  从后端数据库管理系统文件系统读取文件
    --file-write=FIL..  在后端数据库管理系统文件系统上写入本地文件
    --file-dest=FILE..  后端数据库管理系统绝对文件路径

  操作系统访问:
    这些选项可用于访问后端数据库管理系统底层操作系统

    --os-cmd=OSCMD      执行操作系统命令
    --os-shell          提示进行交互式操作系统 shell
    --os-pwn            提示进行 OOB shell、Meterpreter 或 VNC
    --os-smbrelay       一键提示 OOB shell、Meterpreter 或 VNC
    --os-bof            存储过程缓冲区溢出 利用
    --priv-esc          数据库进程用户权限提升
    --msf-path=MSFPATH  Metasploit Framework 的本地安装路径
    --tmp-path=TMPPATH  临时文件目录的远程绝对路径

  Windows 注册表访问:
    这些选项可用于访问后端数据库管理系统 Windows 注册表

    --reg-read          读取 Windows 注册表项值
    --reg-add           写入 Windows 注册表项值数据
    --reg-del           删除 Windows 注册表项值
    --reg-key=REGKEY    Windows 注册表项
    --reg-value=REGVAL  Windows 注册表项值
    --reg-data=REGDATA  Windows 注册表项值数据
    --reg-type=REGTYPE  Windows 注册表项值类型

  一般:
    这些选项可用于设置一些一般工作参数

    -s SESSIONFILE      从存储的 (.sqlite) 文件加载会话
    -t TRAFFICFILE      将所有 HTTP 流量记录到文本文件中
    --abort-on-empty    在空结果时中止数据检索
    --answers=ANSWERS   设置预定义答案 (例如 "quit=N,follow=N")
    --base64=BASE64P..  包含 Base64 编码数据的参数
    --base64-safe       使用 URL 和文件名安全的 Base64 字母表 (RFC 4648)
    --batch             从不要求用户输入，使用默认行为
    --binary-fields=..  具有二进制值的结果字段 (例如 "digest")
    --check-internet    在评估目标之前检查互联网连接
    --cleanup           从数据库管理系统中清除 sqlmap 特定的 UDF 和表
    --crawl=CRAWLDEPTH  从目标 URL 开始爬取网站
    --crawl-exclude=..  正则表达式以排除爬取的页面 (例如 "logout")
    --csv-del=CSVDEL    CSV 输出中使用的分隔字符 (默认 ",")
    --charset=CHARSET   盲 SQL 注入字符集 (例如 "0123456789abcdef")
    --dump-file=DUMP..  将转储的数据存储到自定义文件中
    --dump-format=DU..  转储数据的格式 (CSV (默认), HTML 或 SQLITE)
    --encoding=ENCOD..  用于数据检索的字符编码 (例如 GBK)
    --eta               为每个输出显示预计到达时间
    --flush-session     清空当前目标的会话文件
    --forms             解析并测试目标 URL 上的表单
    --fresh-queries     忽略存储在会话文件中的查询结果
    --gpage=GOOGLEPAGE  使用指定页面编号的 Google dork 结果
    --har=HARFILE       将所有 HTTP 流量记录到 HAR 文件中
    --hex               在数据检索期间使用十六进制转换
    --output-dir=OUT..  自定义输出目录路径
    --parse-errors      解析并显示来自响应的数据库管理系统错误信息
    --preprocess=PRE..  使用给定脚本对请求进行预处理
    --postprocess=PO..  使用给定脚本对响应进行后处理
    --repair            重新转储有未知字符标记的条目 (?)
    --save=SAVECONFIG   将选项保存到配置 INI 文件
    --scope=SCOPE       用于过滤目标的正则表达式
    --skip-heuristics   跳过漏洞的启发式检测
    --skip-waf          跳过 WAF/IPS 保护的启发式检测
    --table-prefix=T..  临时表使用的前缀 (默认: "sqlmap")
    --test-filter=TE..  通过载荷和/或标题选择测试 (例如 ROW)
    --test-skip=TEST..  通过载荷和/或标题跳过测试 (例如 BENCHMARK)
    --time-limit=TIM..  以秒为单位限制运行时间 (例如 3600)
    --unsafe-naming     禁用数据库管理系统标识符的转义 (例如 "user")
    --web-root=WEBROOT  Web 服务器文档根目录 (例如 "/var/www")

  杂项:
    这些选项不适合其他类别

    -z MNEMONICS        使用简短助记符 (例如 "flu,bat,ban,tec=EU")
    --alert=ALERT       在发现 SQL 注入时运行主机操作系统命令
    --beep              在提问时和/或在发现漏洞时发出哔声
    --dependencies      检查缺少的 (可选) sqlmap 依赖项
    --disable-coloring  禁用控制台输出着色
    --list-tampers      显示可用篡改脚本的列表
    --no-logging        禁用日志记录到文件
    --offline           在离线模式下工作 (仅使用会话数据)
    --purge             安全地从 sqlmap 数据目录中删除所有内容
    --results-file=R..  在多个目标模式中 CSV 结果文件的位置
    --shell             提示进行交互式 sqlmap shell
    --tmp-dir=TMPDIR    用于存储临时文件的本地目录
    --unstable          调整不稳定连接的选项
    --update            更新 sqlmap
    --wizard            初学者用户的简单向导界面
''''
