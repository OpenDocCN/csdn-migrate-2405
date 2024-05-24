# Linux Shell 编程秘籍（四）

> 原文：[`zh.annas-archive.org/md5/ABA4B56CB4F69896DB2E9CFE0817AFEF`](https://zh.annas-archive.org/md5/ABA4B56CB4F69896DB2E9CFE0817AFEF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：纠缠的网络？一点也不！

在本章中，我们将涵盖：

+   从网页下载

+   将网页下载为格式化的纯文本

+   cURL 入门

+   从命令行访问未读的 Gmail 邮件

+   从网站解析数据

+   创建图像爬虫和下载器

+   创建网页相册生成器

+   构建 Twitter 命令行客户端

+   定义具有 Web 后端的实用程序

+   在网站中查找损坏的链接

+   跟踪网站的更改

+   发布到网页并读取响应

# 介绍

网络正在成为技术的面孔。这是数据处理的中心访问点。虽然 shell 脚本不能像 PHP 等语言在 Web 上做的那样，但仍然有许多任务适合使用 shell 脚本。在本章中，我们将探讨一些可以用于解析网站内容、下载和获取数据、发送数据到表单以及自动执行网站使用任务和类似活动的方法。我们可以用几行脚本自动执行许多我们通过浏览器交互执行的活动。通过命令行实用程序访问 HTTP 协议提供的功能，我们可以编写适合解决大多数 Web 自动化实用程序的脚本。在阅读本章的食谱时玩得开心。

# 从网页下载

从给定 URL 下载文件或网页很简单。有几个命令行下载实用程序可用于执行此任务。

## 准备就绪

`wget`是一个文件下载命令行实用程序。它非常灵活，可以配置许多选项。

## 如何做...

可以使用`wget`下载网页或远程文件，如下所示：

```
$ wget URL

```

例如：

```
$ wget http://slynux.org 
--2010-08-01 07:51:20--  http://slynux.org/ 
Resolving slynux.org... 174.37.207.60 
Connecting to slynux.org|174.37.207.60|:80... connected. 
HTTP request sent, awaiting response... 200 OK 
Length: 15280 (15K) [text/html] 
Saving to: "index.html" 

100%[======================================>] 15,280      75.3K/s   in 0.2s 

2010-08-01 07:51:21 (75.3 KB/s) - "index.html" saved [15280/15280]

```

也可以指定多个下载 URL，如下所示：

```
$ wget URL1 URL2 URL3 ..

```

可以使用 URL 下载文件，如下所示：

```
$ wget ftp://example_domain.com/somefile.img

```

通常，文件以与 URL 相同的文件名下载，并且下载日志信息或进度被写入`stdout`。

您可以使用`-O`选项指定输出文件名。如果指定的文件名已经存在，它将首先被截断，然后下载的文件将被写入指定的文件。

您还可以使用`-o`选项指定不同的日志文件路径，而不是将日志打印到`stdout`，如下所示：

```
$ wget ftp://example_domain.com/somefile.img -O dloaded_file.img -o log

```

通过使用上述命令，屏幕上将不会打印任何内容。日志或进度将被写入`log`，输出文件将是`dloaded_file.img`。

由于不稳定的互联网连接可能会导致下载中断，因此我们可以使用尝试次数作为参数，以便一旦中断，实用程序将在放弃之前重试下载那么多次。

为了指定尝试次数，请使用`-t`标志，如下所示：

```
$ wget -t 5 URL

```

## 还有更多...

`wget`实用程序有几个额外的选项，可以在不同的问题领域下使用。让我们来看看其中的一些。

### 限速下载

当我们有限的互联网下行带宽和许多应用程序共享互联网连接时，如果给定一个大文件进行下载，它将吸取所有带宽，可能导致其他进程因带宽不足而挨饿。`wget`命令带有一个内置选项，可以指定下载作业可以拥有的最大带宽限制。因此，所有应用程序可以同时平稳运行。

我们可以使用`--limit-rate`参数限制`wget`的速度，如下所示：

```
$ wget  --limit-rate 20k http://example.com/file.iso

```

在这个命令中，`k`（千字节）和`m`（兆字节）指定了速度限制。

我们还可以指定下载的最大配额。当配额超过时，它将停止。在下载多个受总下载大小限制的文件时很有用。这对于防止下载意外使用太多磁盘空间很有用。

使用`--quota`或`-Q`如下：

```
$ wget -Q 100m http://example.com/file1 http://example.com/file2

```

### 恢复下载并继续

如果使用`wget`下载在完成之前中断，我们可以使用`-c`选项恢复下载，从我们离开的地方继续下载，如下所示：

```
$ wget -c URL

```

### 使用 cURL 进行下载

cURL 是另一个高级命令行实用程序。它比 wget 更强大。

cURL 可以用于下载如下：

```
$ curl http://slynux.org > index.html

```

与 wget 不同，curl 将下载的数据写入标准输出（stdout）而不是文件。因此，我们必须使用重定向运算符将数据从 stdout 重定向到文件。

### 复制完整的网站（镜像）

wget 有一个选项，可以通过递归收集网页中的所有 URL 链接并像爬虫一样下载所有网页，从而下载完整的网站。因此，我们可以完全下载网站的所有页面。

为了下载页面，请使用--mirror 选项如下：

```
$ wget --mirror exampledomain.com

```

或使用：

```
$ wget -r -N -l DEPTH URL

```

-l 指定网页的深度为级别。这意味着它只会遍历那么多级别。它与-r（递归）一起使用。-N 参数用于为文件启用时间戳。URL 是需要启动下载的网站的基本 URL。

### 使用 HTTP 或 FTP 身份验证访问页面

有些网页需要对 HTTP 或 FTP URL 进行身份验证。这可以通过使用--user 和--password 参数来提供：

```
$ wget –-user username –-password pass URL

```

还可以在不指定内联密码的情况下请求密码。为此，请使用--ask-password 而不是--password 参数。

# 将网页作为格式化纯文本下载

网页是包含一系列 HTML 标记以及其他元素（如 JavaScript、CSS 等）的 HTML 页面。但是 HTML 标记定义了网页的基础。在查找特定内容时，我们可能需要解析网页中的数据，这是 Bash 脚本可以帮助我们的地方。当我们下载一个网页时，我们会收到一个 HTML 文件。为了查看格式化的数据，它应该在 Web 浏览器中查看。然而，在大多数情况下，解析格式化的文本文档将比解析 HTML 数据更容易。因此，如果我们可以获得一个与在 Web 浏览器上看到的网页类似的格式化文本的文本文件，那将更有用，并且可以节省大量去除 HTML 标记所需的工作。Lynx 是一个有趣的命令行 Web 浏览器。我们实际上可以从 Lynx 获取网页作为纯文本格式化输出。让我们看看如何做到这一点。

## 如何做…

让我们使用 lynx 命令的--dump 标志将网页视图以 ASCII 字符表示形式下载到文本文件中：

```
$ lynx -dump URL > webpage_as_text.txt

```

该命令还将所有超链接（<a href="link">）单独列在文本输出的页脚下的**References**标题下。这将帮助我们避免使用正则表达式单独解析链接。

例如：

```
$ lynx -dump http://google.com > plain_text_page.txt

```

您可以使用 cat 命令查看文本的纯文本版本如下：

```
$ cat plain_text_page.txt

```

# cURL 入门

cURL 是一个强大的实用程序，支持包括 HTTP、HTTPS、FTP 等在内的许多协议。它支持许多功能，包括 POST、cookie、身份验证、从指定偏移量下载部分文件、引用、用户代理字符串、额外标头、限制速度、最大文件大小、进度条等。cURL 对于我们想要玩转自动化网页使用序列并检索数据时非常有用。这个配方是 cURL 最重要的功能列表。

## 准备工作

cURL 不会默认随主要 Linux 发行版一起提供，因此您可能需要使用软件包管理器安装它。默认情况下，大多数发行版都附带 wget。

cURL 通常将下载的文件转储到 stdout，并将进度信息转储到 stderr。为了避免显示进度信息，我们总是使用--silent 选项。

## 如何做…

curl 命令可用于执行不同的活动，如下载、发送不同的 HTTP 请求、指定 HTTP 标头等。让我们看看如何使用 cURL 执行不同的任务。

```
$ curl URL --silent

```

上述命令将下载的文件转储到终端（下载的数据写入 stdout）。

`--silent`选项用于防止`curl`命令显示进度信息。如果需要进度信息，请删除`--silent`。

```
$ curl URL –-silent -O

```

使用`-O`选项将下载的数据写入文件，文件名从 URL 中解析而不是写入标准输出。

例如：

```
$ curl http://slynux.org/index.html --silent -O

```

将创建`index.html`。

它将网页或文件写入与 URL 中的文件名相同的文件，而不是写入`stdout`。如果 URL 中没有文件名，将产生错误。因此，请确保 URL 是指向远程文件的 URL。`curl http://slynux.org -O --silent`将显示错误，因为无法从 URL 中解析文件名。

```
$ curl URL –-silent -o new_filename

```

`-o`选项用于下载文件并写入指定的文件名。

为了在下载时显示`#`进度条，使用`--progress`而不是`--silent`。

```
$ curl http://slynux.org -o index.html --progress
################################## 100.0% 

```

## 还有更多...

在前面的部分中，我们已经学习了如何下载文件并将 HTML 页面转储到终端。cURL 还有一些高级选项。让我们更深入地了解 cURL。

### 继续/恢复下载

cURL 具有高级的恢复下载功能，可以在给定的偏移量继续下载，而`wget`不具备这个功能。它可以通过指定偏移量来下载文件的部分。

```
$ curl URL/file -C offset

```

偏移是以字节为单位的整数值。

如果我们想要恢复下载文件，cURL 不需要我们知道确切的字节偏移量。如果要 cURL 找出正确的恢复点，请使用`-C -`选项，就像这样：

```
$ curl -C - URL

```

cURL 将自动找出重新启动指定文件的下载位置。

### 使用 cURL 设置引用字符串

引用者是 HTTP 头中的一个字符串，用于标识用户到达当前网页的页面。当用户从网页 A 点击链接到达网页 B 时，页面 B 中的引用头字符串将包含页面 A 的 URL。

一些动态页面在返回 HTML 数据之前会检查引用字符串。例如，当用户通过在 Google 上搜索导航到网站时，网页会显示一个附加了 Google 标志的页面，当他们通过手动输入 URL 导航到网页时，会显示不同的页面。

网页可以编写一个条件，如果引用者是[www.google.com](http://www.google.com)，则返回一个 Google 页面，否则返回一个不同的页面。

您可以使用`curl`命令的`--referer`选项指定引用字符串如下：

```
$ curl –-referer Referer_URL target_URL

```

例如：

```
$ curl –-referer http://google.com http://slynux.org

```

### 使用 cURL 的 cookies

使用`curl`我们可以指定并存储在 HTTP 操作期间遇到的 cookies。

为了指定 cookies，使用`--cookie "COOKIES"`选项。

Cookies 应该提供为`name=value`。多个 cookies 应该用分号“;”分隔。例如：

```
$ curl http://example.com –-cookie "user=slynux;pass=hack"

```

为了指定存储遇到的 cookies 的文件，使用`--cookie-jar`选项。例如：

```
$ curl URL –-cookie-jar cookie_file

```

### 使用 cURL 设置用户代理字符串

一些检查用户代理的网页如果没有指定用户代理就无法工作。您可能已经注意到，某些网站只在 Internet Explorer（IE）中运行良好。如果使用不同的浏览器，网站将显示一个消息，表示只能在 IE 上运行。这是因为网站检查用户代理。您可以使用`curl`将用户代理设置为 IE，并查看在这种情况下返回不同的网页。

使用 cURL 可以使用`--user-agent`或`-A`来设置如下：

```
$ curl URL –-user-agent "Mozilla/5.0"

```

可以使用 cURL 传递附加的标头。使用`-H "Header"`传递多个附加标头。例如：

```
$ curl -H "Host: www.slynux.org" -H "Accept-language: en" URL

```

### 在 cURL 上指定带宽限制

当可用带宽有限且多个用户共享互联网时，为了平稳地共享带宽，我们可以通过使用`--limit-rate`选项从`curl`限制下载速率到指定的限制。

```
$ curl URL --limit-rate 20k

```

在这个命令中，`k`（千字节）和`m`（兆字节）指定了下载速率限制。

### 指定最大下载大小

可以使用`--max-filesize`选项指定 cURL 的最大下载文件大小如下：

```
$ curl URL --max-filesize bytes

```

如果文件大小超过，则返回非零退出代码。如果成功，则返回零。

### 使用 cURL 进行身份验证

可以使用 cURL 和`-u`参数进行 HTTP 身份验证或 FTP 身份验证。

可以使用`-u username:password`指定用户名和密码。也可以不提供密码，这样在执行时会提示输入密码。

如果您希望提示输入密码，可以仅使用`-u username`。例如：

```
$ curl -u user:pass http://test_auth.com

```

为了提示输入密码，请使用：

```
$ curl -u user http://test_auth.com 

```

### 打印响应标头，不包括数据

仅打印响应标头非常有用，可以应用许多检查或统计。例如，要检查页面是否可访问，我们不需要下载整个页面内容。只需读取 HTTP 响应标头即可用于识别页面是否可用。

检查 HTTP 标头的一个示例用例是在下载之前检查文件大小。我们可以检查 HTTP 标头中的`Content-Length`参数以找出文件的长度。还可以从标头中检索到几个有用的参数。`Last-Modified`参数使我们能够知道远程文件的最后修改时间。

使用`curl`的`–I`或`–head`选项仅转储 HTTP 标头而不下载远程文件。例如：

```
$ curl -I http://slynux.org
HTTP/1.1 200 OK 
Date: Sun, 01 Aug 2010 05:08:09 GMT 
Server: Apache/1.3.42 (Unix) mod_gzip/1.3.26.1a mod_log_bytes/1.2 mod_bwlimited/1.4 mod_auth_passthrough/1.8 FrontPage/5.0.2.2635 mod_ssl/2.8.31 OpenSSL/0.9.7a 
Last-Modified: Thu, 19 Jul 2007 09:00:58 GMT 
ETag: "17787f3-3bb0-469f284a" 
Accept-Ranges: bytes 
Content-Length: 15280 
Connection: close 
Content-Type: text/html

```

## 参见

+   *发布到网页并读取响应*

# 从命令行访问 Gmail

Gmail 是谷歌提供的广泛使用的免费电子邮件服务[: http://mail.google.com/](http://: http://mail.google.com/)。 Gmail 允许您通过经过身份验证的 RSS 订阅来阅读邮件。我们可以解析 RSS 订阅，其中包括发件人的姓名和主题为电子邮件。这将有助于在不打开网络浏览器的情况下查看收件箱中的未读邮件。

## 如何做...

让我们通过 shell 脚本来解析 Gmail 的 RSS 订阅以显示未读邮件：

```
#!/bin/bash
Filename: fetch_gmail.sh
#Description: Fetch gmail tool

username="PUT_USERNAME_HERE"
password="PUT_PASSWORD_HERE"

SHOW_COUNT=5 # No of recent unread mails to be shown

echo

curl  -u $username:$password --silent "https://mail.google.com/mail/feed/atom" | \
tr -d '\n' | sed 's:</entry>:\n:g' |\
 sed 's/.*<title>\(.*\)<\/title.*<author><name>\([^<]*\)<\/name><email>\([^<]*\).*/Author: \2 [\3] \nSubject: \1\n/' | \
head -n $(( $SHOW_COUNT * 3 ))
```

输出将如下所示：

```
$ ./fetch_gmail.sh
Author: SLYNUX [ slynux@slynux.com ]
Subject: Book release - 2

Author: SLYNUX [ slynux@slynux.com ]
Subject: Book release - 1
.
… 5 entries

```

## 它是如何工作的...

该脚本使用 cURL 通过用户身份验证下载 RSS 订阅。用户身份验证由`-u username:password`参数提供。您可以使用`-u user`而不提供密码。然后在执行 cURL 时，它将交互式地要求输入密码。

在这里，我们可以将管道命令拆分为不同的块，以说明它们的工作原理。

`tr -d '\n'`删除换行符，以便我们使用`\n`作为分隔符重构每个邮件条目。`sed 's:</entry>:\n:g'`将每个`</entry>`替换为换行符，以便每个邮件条目都由换行符分隔，因此可以逐个解析邮件。查看[`mail.google.com/mail/feed/atom`](https://mail.google.com/mail/feed/atom)的源代码，了解 RSS 订阅中使用的 XML 标记。`<entry> TAGS </entry>`对应于单个邮件条目。

下一个脚本块如下：

```
 sed 's/.*<title>\(.*\)<\/title.*<author><name>\([^<]*\)<\/name><email>\([^<]*\).*/Author: \2 [\3] \nSubject: \1\n/'
```

此脚本使用`<title>\(.*\)<\/title`匹配子字符串标题，使用`<author><name>\([^<]*\)<\/name>`匹配发件人姓名，使用`<email>\([^<]*\)`匹配电子邮件。然后使用反向引用如下：

+   `Author: \2 [\3] \nSubject: \1\n`用于以易于阅读的格式替换邮件的条目。`\1`对应于第一个子字符串匹配，`\2`对应于第二个子字符串匹配，依此类推。

+   `SHOW_COUNT=5`变量用于在终端上打印未读邮件条目的数量。

+   `head`用于仅显示来自第一行的`SHOW_COUNT*3`行。 `SHOW_COUNT`被使用三次，以便显示输出的三行。

## 参见

+   *cURL 入门*，解释了 curl 命令

+   *基本的 sed 入门*第四章，解释了 sed 命令

# 从网站解析数据

通过消除不必要的细节，从网页中解析数据通常很有用。`sed`和`awk`是我们将用于此任务的主要工具。您可能已经在上一章的 grep 示例中看到了一个访问排名列表；它是通过解析网站页面[`www.johntorres.net/BoxOfficefemaleList.html`](http://www.johntorres.net/BoxOfficefemaleList.html)生成的。

让我们看看如何使用文本处理工具解析相同的数据。

## 如何做...

让我们通过用于解析女演员详情的命令序列：

```
$ lynx -dump http://www.johntorres.net/BoxOfficefemaleList.html  | \ grep -o "Rank-.*" | \
sed 's/Rank-//; s/\[[0-9]\+\]//' | \
sort -nk 1 |\
 awk ' 
{
 for(i=3;i<=NF;i++){ $2=$2" "$i } 
 printf "%-4s %s\n", $1,$2 ; 
}' > actresslist.txt

```

输出将如下所示：

```
# Only 3 entries shown. All others omitted due to space limits
1   Keira Knightley 
2   Natalie Portman 
3   Monica Bellucci 

```

## 它是如何工作的...

Lynx 是一个命令行网页浏览器；它可以转储网站的文本版本，就像我们在网页浏览器中看到的那样，而不是显示原始代码。因此，它避免了删除 HTML 标记的工作。我们使用`sed`解析以 Rank 开头的行，如下所示：

```
sed 's/Rank-//; s/\[[0-9]\+\]//'
```

然后可以根据排名对这些行进行排序。这里使用`awk`来保持排名和名称之间的间距，通过指定宽度来使其统一。`%-4s`指定四个字符的宽度。除了第一个字段之外的所有字段都被连接在一起形成一个单个字符串`$2`。

## 另请参阅

+   *第四章的基本 sed 入门*，解释了 sed 命令

+   *第四章的基本 awk 入门*，解释了 awk 命令

+   *以格式化纯文本形式下载网页*，解释了 lynx 命令

# 图像爬虫和下载器

当我们需要下载出现在网页中的所有图像时，图像爬虫非常有用。我们可以使用脚本来解析图像文件并自动下载，而不是查看 HTML 源并选择所有图像。让我们看看如何做到这一点。

## 如何做...

让我们编写一个 Bash 脚本来爬取并从网页下载图像，如下所示：

```
#!/bin/bash
#Description: Images downloader
#Filename: img_downloader.sh

if [ $# -ne 3 ];
then
  echo "Usage: $0 URL -d DIRECTORY"
  exit -1
fi

for i in {1..4}
do
  case $1 in
  -d) shift; directory=$1; shift ;;
   *) url=${url:-$1}; shift;;
esac
done

mkdir -p $directory;
baseurl=$(echo $url | egrep -o "https?://[a-z.]+")

curl –s $url | egrep -o "<img src=[^>]*>" | sed 's/<img src=\"\([^"]*\).*/\1/g' > /tmp/$$.list

sed -i "s|^/|$baseurl/|" /tmp/$$.list

cd $directory;

while read filename;
do
  curl –s -O "$filename" --silent

done < /tmp/$$.list
```

一个示例用法如下：

```
$ ./img_downloader.sh http://www.flickr.com/search/?q=linux -d images

```

## 它是如何工作的...

上述图像下载器脚本解析 HTML 页面，除了`<img>`之外剥离所有标记，然后从`<img>`标记中解析`src="img/URL"`并将其下载到指定目录。此脚本接受网页 URL 和目标目录路径作为命令行参数。脚本的第一部分是解析命令行参数的一种巧妙方法。`[ $# -ne 3 ]`语句检查脚本的参数总数是否为三，否则退出并返回一个使用示例。

如果有 3 个参数，那么解析 URL 和目标目录。为了做到这一点，使用了一个巧妙的技巧：

```
for i in {1..4}
do 
 case $1 in
 -d) shift; directory=$1; shift ;;
 *) url=${url:-$1}; shift;;
esac
done

```

`for`循环迭代了四次（数字四没有特殊意义，只是为了运行`case`语句几次）。

`case`语句将评估第一个参数（`$1`），并匹配`-d`或任何其他检查的字符串参数。我们可以在格式中的任何位置放置`-d`参数，如下所示：

```
$ ./img_downloader.sh -d DIR URL

```

或：

```
$ ./img_downloader.sh URL -d DIR

```

`shift`用于移动参数，这样当调用`shift`时，`$1`将被赋值为`$2`，再次调用时，`$1=$3`，依此类推，因为它将`$1`移动到下一个参数。因此，我们可以通过`$1`本身评估所有参数。

当匹配`-d`（`-d)`）时，很明显下一个参数是目标目录的值。`*）`对应默认匹配。它将匹配除`-d`之外的任何内容。因此，在迭代时，`$1=""`或`$1=URL`在默认匹配中，我们需要取`$1=URL`避免`""`覆盖。因此我们使用`url=${url:-$1}`技巧。如果已经不是`""`，它将返回一个 URL 值，否则它将分配`$1`。

`egrep -o "<img src=[^>]*>"`将仅打印匹配的字符串，即包括其属性的`<img>`标记。`[^>]*`用于匹配除了结束`>`之外的所有字符，即`<img src="img/image.jpg" …. >`。

`sed 's/<img src=\"\([^"]*\).*/\1/g'`解析`src="img/url"`，以便可以从已解析的`<img>`标记中解析所有图像 URL。

有两种类型的图像源路径：相对和绝对。绝对路径包含以`http://`或`https://`开头的完整 URL。相对 URL 以`/`或`image_name`本身开头。

绝对 URL 的示例是：[`example.com/image.jpg`](http://example.com/image.jpg)

相对 URL 的示例是：`/image.jpg`

对于相对 URL，起始的`/`应该被替换为基本 URL，以将其转换为[`example.com/image.jpg`](http://example.com/image.jpg)。

为了进行转换，我们首先通过解析找出`baseurl sed`。

然后用`sed -i "s|^/|$baseurl/|" /tmp/$$.list`将起始的`/`替换为`baseurl sed`。

然后使用`while`循环逐行迭代列表，并使用`curl`下载 URL。使用`--silent`参数与`curl`一起，以避免在屏幕上打印其他进度消息。

## 另请参阅

+   *cURL 入门*，解释了 curl 命令

+   *基本的 sed 入门* 第四章 ，解释 sed 命令

+   *使用 grep 在文件中搜索和挖掘“文本”* 第四章 ，解释 grep 命令

# Web 相册生成器

Web 开发人员通常为网站设计照片相册页面，该页面包含页面上的许多图像缩略图。单击缩略图时，将显示图片的大版本。但是，当需要许多图像时，每次复制`<img>`标签，调整图像以创建缩略图，将它们放在 thumbs 目录中，测试链接等都是真正的障碍。这需要很多时间并且重复相同的任务。通过编写一个简单的 Bash 脚本，可以轻松自动化。通过编写脚本，我们可以在几秒钟内自动创建缩略图，将它们放在确切的目录中，并自动生成`<img>`标签的代码片段。这个配方将教你如何做到这一点。

## 准备工作

我们可以使用`for`循环执行此任务，该循环遍历当前目录中的每个图像。通常使用 Bash 实用程序，如`cat`和`convert`（image magick）。这些将生成一个 HTML 相册，使用所有图像，放在`index.html`中。为了使用`convert`，请确保已安装 Imagemagick。

## 如何做...

让我们编写一个 Bash 脚本来生成 HTML 相册页面：

```
#!/bin/bash
#Filename: generate_album.sh
#Description: Create a photo album using images in current directory

echo "Creating album.."
mkdir -p thumbs
cat <<EOF > index.html
<html>
<head>
<style>

body 
{ 
  width:470px;
  margin:auto;
  border: 1px dashed grey;
  padding:10px; 
} 

img
{ 
  margin:5px;
  border: 1px solid black;

} 
</style>
</head>
<body>
<center><h1> #Album title </h1></center>
<p>
EOF

for img in *.jpg;
do 
  convert "$img" -resize "100x" "thumbs/$img"
  echo "<a href=\"$img\" ><img src=\"thumbs/$img\" title=\"$img\" /></a>" >> index.html
done

cat <<EOF >> index.html

</p>
</body>
</html>
EOF 

echo Album generated to index.html
```

按以下方式运行脚本：

```
$ ./generate_album.sh
Creating album..
Album generated to index.html

```

## 工作原理...

脚本的初始部分是编写 HTML 页面的标题部分。

以下脚本将所有内容重定向到 EOF（不包括）到`index.html`：

```
cat <<EOF > index.html
contents...
EOF
```

标题包括 HTML 和样式表。

`for img in *.jpg;`将遍历每个文件的名称并执行操作。

`convert "$img" -resize "100x" "thumbs/$img"`将创建宽度为 100px 的图像作为缩略图。

以下语句将生成所需的`<img>`标签并将其附加到`index.html`：

```
echo "<a href=\"$img\" ><img src=\"thumbs/$img\" title=\"$img\" /></a>" >> index.html
```

最后，使用`cat`附加页脚 HTML 标记。

## 另请参阅

+   *玩转文件描述符和重定向* 第一章 ，解释 EOF 和 stdin 重定向。

# Twitter 命令行客户端

Twitter 是最热门的微博平台，也是在线社交媒体的最新热点。发推文和阅读推文很有趣。如果我们可以从命令行做这两件事呢？编写命令行 Twitter 客户端非常简单。Twitter 有 RSS feeds，因此我们可以利用它们。让我们看看如何做到这一点。

## 准备工作

我们可以使用 cURL 进行身份验证并发送 twitter 更新，以及下载 RSS feed 页面以解析 tweets。只需四行代码就可以做到。让我们来做吧。

## 如何做...

让我们编写一个 Bash 脚本，使用`curl`命令来操作 twitter API：

```
#!/bin/bash
#Filename: tweets.sh
#Description: Basic twitter client

USERNAME="PUT_USERNAME_HERE"
PASSWORD="PUT_PASSWORD_HERE"
COUNT="PUT_NO_OF_TWEETS"

if [[ "$1" != "read" ]] && [[ "$1" != "tweet" ]];
then 
  echo -e "Usage: $0 send status_message\n   OR\n      $0 read\n"
  exit -1;
fi

if [[ "$1" = "read" ]];
then 
  curl --silent -u $USERNAME:$PASSWORD  http://twitter.com/statuses/friends_timeline.rss | \
grep title | \
tail -n +2 | \
head -n $COUNT | \
  sed 's:.*<title>\([^<]*\).*:\n\1:'

elif [[ "$1" = "tweet" ]];
then 
  status=$( echo $@ | tr -d '"' | sed 's/.*tweet //')
  curl --silent -u $USERNAME:$PASSWORD -d status="$status" http://twitter.com/statuses/update.xml > /dev/null
  echo 'Tweeted :)'
fi
```

运行以下脚本：

```
$ ./tweets.sh tweet Thinking of writing a X version of wall command "#bash"
Tweeted :)

$ ./tweets.sh read
bot: A tweet line
t3rm1n4l: Thinking of writing a X version of wall command #bash

```

## 工作原理...

让我们通过将上述脚本分成两部分来看看它的工作。第一部分是关于阅读推文的。要阅读推文，脚本会从[`twitter.com/statuses/friends_timeline.rss`](http://twitter.com/statuses/friends_timeline.rss)下载 RSS 信息，并解析包含`<title>`标签的行。然后，它使用`sed`剥离`<title>`和`</title>`标签，以形成所需的推文文本。然后使用`COUNT`变量来使用`head`命令除了最近推文的数量之外的所有其他文本。使用`tail -n +2`来删除不必要的标题文本“Twitter: Timeline of friends”。

在发送推文部分，`curl`的`-d`状态参数用于使用 Twitter 的 API 发布数据到 Twitter：[`twitter.com/statuses/update.xml`](http://twitter.com/statuses/update.xml)。

在发送推文的情况下，脚本的`$1`将是推文。然后，为了获取状态，我们使用`$@`（脚本的所有参数的列表）并从中删除单词“tweet”。

## 另请参阅

+   *cURL 入门*，解释了 curl 命令

+   *头和尾-打印最后或前 10 行* 第三章，解释了头和尾命令

# 具有 Web 后端的定义实用程序

谷歌通过使用搜索查询`define:WORD`为任何单词提供 Web 定义。我们需要一个 GUI 网页浏览器来获取定义。但是，我们可以通过使用脚本来自动化并解析所需的定义。让我们看看如何做到这一点。

## 准备工作

我们可以使用`lynx`，`sed`，`awk`和`grep`来编写定义实用程序。

## 如何做...

让我们看看从 Google 搜索中获取定义的定义实用程序脚本的核心部分：

```
#!/bin/bash
#Filename: define.sh
#Description: A Google define: frontend

limit=0
if  [ ! $# -ge 1 ];
then
  echo -e "Usage: $0 WORD [-n No_of_definitions]\n"
  exit -1;
fi

if [ "$2" = "-n" ];
then
  limit=$3;
  let limit++
fi

word=$1

lynx -dump http://www.google.co.in/search?q=define:$word | \
awk '/Defini/,/Find defini/' | head -n -1 | sed 's:*:\n*:; s:^[ ]*::' | \
grep -v "[[0-9]]" | \
awk '{
if ( substr($0,1,1) == "*" )
{ sub("*",++count".") } ;
print
} ' >  /tmp/$$.txt

echo

if [ $limit -ge 1 ];
then

cat /tmp/$$.txt | sed -n "/¹\./, /${limit}/p" | head -n -1

else

cat /tmp/$$.txt;

fi
```

按以下方式运行脚本：

```
$ ./define.sh hack -n 2
1\. chop: cut with a hacking tool
2\. one who works hard at boring tasks

```

## 它是如何工作的...

我们将研究定义解析器的核心部分。Lynx 用于获取网页的纯文本版本。[`www.google.co.in/search?q=define:$word`](http://www.google.co.in/search?q=define:$word)是网页定义网页的 URL。然后我们缩小“网页上的定义”和“查找定义”之间的文本。所有的定义都出现在这些文本行之间（`awk '/Defini/,/Find defini/'`）。

`'s:*:\n*:'`用于将*替换为*和换行符，以便在每个定义之间插入换行符，`s:^[ ]*::`用于删除行首的额外空格。在 lynx 输出中，超链接标记为[数字]。这些行通过`grep -v`（反向匹配行选项）被移除。然后使用`awk`将出现在行首的*替换为数字，以便为每个定义分配一个序号。如果我们在脚本中读取了一个`-n`计数，它必须根据计数输出一些定义。因此，使用`awk`打印序号 1 到计数的定义（这样做更容易，因为我们用序号替换了*）。

## 另请参阅

+   *基本的 sed 入门* 第四章，解释了 sed 命令

+   *基本的 awk 入门* 第四章，解释了 awk 命令

+   *使用 grep 在文件中搜索和挖掘“文本”* 第四章，解释了 grep 命令

+   *将网页下载为格式化的纯文本*，解释了 lynx 命令

# 在网站中查找损坏的链接

我看到人们手动检查网站上的每个页面以查找损坏的链接。这仅适用于页面非常少的网站。当页面数量变得很多时，这将变得不可能。如果我们可以自动查找损坏的链接，那将变得非常容易。我们可以使用 HTTP 操作工具来查找损坏的链接。让我们看看如何做到这一点。

## 准备工作

为了识别链接并从链接中找到损坏的链接，我们可以使用`lynx`和`curl`。它有一个`-traversal`选项，它将递归访问网站中的页面，并构建网站中所有超链接的列表。我们可以使用 cURL 来验证每个链接是否损坏。

## 如何做...

让我们通过`curl`命令编写一个 Bash 脚本来查找网页上的损坏链接：

```
#!/bin/bash 
#Filename: find_broken.sh
#Description: Find broken links in a website

if [ $# -eq 2 ]; 
then 
  echo -e "$Usage $0 URL\n" 
  exit -1; 
fi 

echo Broken links: 

mkdir /tmp/$$.lynx 

cd /tmp/$$.lynx 

lynx -traversal $1 > /dev/null 
count=0; 

sort -u reject.dat > links.txt 

while read link; 
do 
  output=`curl -I $link -s | grep "HTTP/.*OK"`; 
  if [[ -z $output ]]; 
  then 
    echo $link; 
    let count++ 
  fi 

done < links.txt 

[ $count -eq 0 ] && echo No broken links found.
```

## 工作原理...

`lynx -traversal URL`将在工作目录中生成多个文件。其中包括一个名为`reject.dat`的文件，其中包含网站中的所有链接。使用`sort -u`来避免重复构建列表。然后我们遍历每个链接，并使用`curl -I`检查标题响应。如果标题包含第一行`HTTP/1.0 200 OK`作为响应，这意味着目标不是损坏的。所有其他响应对应于损坏的链接，并打印到`stdout`。

## 另请参阅

+   *以格式化纯文本形式下载网页*，解释了 lynx 命令

+   *cURL 入门*，解释了 curl 命令

# 跟踪网站的变化

跟踪网站的变化对于网页开发人员和用户非常有帮助。在间隔时间内手动检查网站非常困难和不切实际。因此，我们可以编写一个在重复间隔时间内运行的变化跟踪器。当发生变化时，它可以播放声音或发送通知。让我们看看如何编写一个基本的网站变化跟踪器。

## 准备工作

在 Bash 脚本中跟踪网页变化意味着在不同时间获取网站并使用`diff`命令进行差异。我们可以使用`curl`和`diff`来做到这一点。

## 如何做...

让我们通过组合不同的命令来编写一个 Bash 脚本来跟踪网页中的变化：

```
#!/bin/bash
#Filename: change_track.sh
#Desc: Script to track changes to webpage

if [ $# -eq 2 ];
then 
  echo -e "$Usage $0 URL\n"
  exit -1;
fi

first_time=0
# Not first time

if [ ! -e "last.html" ];
then
  first_time=1
  # Set it is first time run
fi

curl --silent $1 -o recent.html

if [ $first_time -ne 1 ];
then
  changes=$(diff -u last.html recent.html)
  if [ -n "$changes" ];
  then
    echo -e "Changes:\n"
    echo "$changes"
  else
    echo -e "\nWebsite has no changes"
  fi
else
  echo "[First run] Archiving.."

fi

cp recent.html last.html
```

让我们看看`track_changes.sh`脚本在网页发生变化和网页未发生变化时的输出：

+   首次运行：

```
$ ./track_changes.sh http://web.sarathlakshman.info/test.html
[First run] Archiving..

```

+   第二次运行：

```
$ ./track_changes.sh http://web.sarathlakshman.info/test.html
Website has no changes 

```

+   对网页进行更改后的第三次运行：

```
$ ./test.sh http://web.sarathlakshman.info/test_change/test.html 
Changes: 

--- last.html	2010-08-01 07:29:15.000000000 +0200 
+++ recent.html	2010-08-01 07:29:43.000000000 +0200 
@@ -1,3 +1,4 @@ 
<html>
+added line :)
<p>data</p>
</html>

```

## 工作原理...

该脚本通过`[！-e`last.html`]`检查脚本是否是第一次运行。如果`last.html`不存在，这意味着这是第一次，因此必须下载网页并将其复制为`last.html`。

如果不是第一次，它应该下载新副本（`recent.html`）并使用`diff`实用程序检查差异。如果有变化，它应该打印出变化，最后应该将`recent.html`复制到`last.html`。

## 另请参阅

+   *cURL 入门*，解释了 curl 命令

# 向网页提交并读取响应

POST 和 GET 是 HTTP 中用于向网站发送信息或检索信息的两种请求类型。在 GET 请求中，我们通过网页 URL 本身发送参数（名称-值对）。在 POST 的情况下，它不会附加在 URL 上。当需要提交表单时使用 POST。例如，需要提交用户名、密码和检索登录页面。

在编写基于网页检索的脚本时，POST 到页面的使用频率很高。让我们看看如何使用 POST。通过发送 POST 数据和检索输出来自动执行 HTTP GET 和 POST 请求是我们在编写从网站解析数据的 shell 脚本时练习的非常重要的任务。

## 准备工作

cURL 和`wget`都可以通过参数处理 POST 请求。它们作为名称-值对传递。

## 如何做...

让我们看看如何使用`curl`从真实网站进行 POST 和读取 HTML 响应：

```
$ curl URL -d "postvar=postdata2&postvar2=postdata2"

```

我们有一个网站（[`book.sarathlakshman.com/lsc/mlogs/`](http://book.sarathlakshman.com/lsc/mlogs/)），用于提交当前用户信息，如主机名和用户名。假设在网站的主页上有两个字段 HOSTNAME 和 USER，以及一个 SUBMIT 按钮。当用户输入主机名、用户名并单击 SUBMIT 按钮时，详细信息将存储在网站中。可以使用一行`curl`命令自动化此过程，通过自动化 POST 请求。如果查看网站源代码（使用 Web 浏览器的查看源代码选项），可以看到类似于以下代码的 HTML 表单定义：

```
<form action="http://book.sarathlakshman.com/lsc/mlogs/submit.php" method="post" >

<input type="text" name="host" value="HOSTNAME" >
<input type="text" name="user" value="USER" >
<input type="submit" >
</form>
```

在这里，[`book.sarathlakshman.com/lsc/mlogs/submit.php`](http://book.sarathlakshman.com/lsc/mlogs/submit.php)是目标 URL。当用户输入详细信息并单击提交按钮时，主机和用户输入将作为 POST 请求发送到`submit.php`，并且响应页面将返回到浏览器。

我们可以按照以下方式自动化 POST 请求：

```
$ curl http://book.sarathlakshman.com/lsc/mlogs/submit.php -d "host=test-host&user=slynux"
<html>
You have entered :
<p>HOST : test-host</p>
<p>USER : slynux</p>
<html>

```

现在`curl`返回响应页面。

`-d`是用于发布的参数。 `-d`的字符串参数类似于 GET 请求语义。 `var=value`对应关系应该由`&`分隔。

### 注意

`-d`参数应该总是用引号括起来。如果不使用引号，`&`会被 shell 解释为表示这应该是一个后台进程。

## 还有更多

让我们看看如何使用 cURL 和`wget`执行 POST。

### 在 curl 中进行 POST

您可以使用`-d`或`–data`在`curl`中发送 POST 数据，如下所示：

```
$ curl –-data "name=value" URL -o output.html

```

如果要发送多个变量，请用`&`分隔它们。请注意，当使用`&`时，名称-值对应该用引号括起来，否则 shell 将把`&`视为后台进程的特殊字符。例如：

```
$ curl -d "name1=val1&name2=val2" URL -o output.html

```

### 使用 wget 发送 POST 数据

您可以使用`wget`通过使用`-–post-data "string"`来发送 POST 数据。例如：

```
$ wget URL –post-data "name=value" -O output.html

```

使用与 cURL 相同的格式进行名称-值对。

## 另请参阅

+   *关于 cURL 的入门*，解释了 curl 命令

+   *从网页下载*解释了 wget 命令


# 第六章：备份计划

在本章中，我们将涵盖：

+   使用 tar 进行存档

+   使用 cpio 进行存档

+   使用 gunzip（gzip）进行压缩

+   使用 bunzip（bzip）进行压缩

+   使用 lzma 进行压缩

+   使用 zip 进行存档和压缩

+   重压缩 squashfs 文件系统

+   使用标准算法对文件和文件夹进行加密

+   使用 rsync 备份快照

+   使用 git 进行版本控制备份

+   使用 dd 进行克隆磁盘

# 介绍

数据的快照和备份是我们经常遇到的常规任务。当涉及到服务器或大型数据存储系统时，定期备份非常重要。可以通过 shell 脚本自动化备份。存档和压缩似乎在系统管理员或普通用户的日常生活中找到了用途。有各种压缩格式可以以各种方式使用，以便获得最佳结果。加密是另一个经常使用的任务，用于保护数据。为了减小加密数据的大小，通常在加密之前对文件进行存档和压缩。有许多标准的加密算法可供使用，并且可以使用 shell 实用程序进行处理。本章将介绍使用 shell 创建和维护文件或文件夹存档、压缩格式和加密技术的不同方法。让我们来看看这些方法。

# 使用 tar 进行存档

`tar`命令可用于存档文件。它最初是为了在磁带存档上存储数据而设计的。它允许您将多个文件和目录存储为单个文件。它可以保留所有文件属性，如所有者、权限等。`tar`命令创建的文件通常被称为 tarball。

## 准备就绪

`tar`命令默认随所有类 UNIX 操作系统一起提供。它具有简单的语法，并且是一种可移植的文件格式。让我们看看如何做到这一点。

`tar`有一系列参数：`A`、`c`、`d`、`r`、`t`、`u`、`x`、`f`和`v`。每个字母都可以独立使用，用于相应的不同目的。

## 如何做到…

要使用 tar 存档文件，请使用以下语法：

```
$ tar -cf output.tar [SOURCES]

```

例如：

```
$ tar -cf output.tar file1 file2 file3 folder1 ..

```

在这个命令中，`-c`代表“创建文件”，`–f`代表“指定文件名”。

我们可以将文件夹和文件名指定为`SOURCES`。我们可以使用文件名列表或通配符，如`*.txt`来指定源。

它将源文件存档到名为`output.tar`的文件中。

文件名必须立即出现在`–f`之后，并且应该是参数组中的最后一个选项（例如，`-cvvf filename.tar`和`-tvvf filename.tar`）。

我们不能将数百个文件或文件夹作为命令行参数传递，因为有限制。因此，如果要存档许多文件，最好使用附加选项。

## 还有更多…

让我们看看`tar`命令提供的其他功能。

### 将文件附加到存档中

有时我们可能需要将文件添加到已经存在的存档中（一个示例用法是当需要存档数千个文件时，无法将它们作为命令行参数在一行中指定）。

附加选项：`-r`

为了将文件附加到已经存在的存档中使用：

```
$ tar -rvf original.tar new_file

```

按如下方式列出存档中的文件：

```
$ tar -tf archive.tar
yy/lib64/
yy/lib64/libfakeroot/
yy/sbin/

```

为了在存档或列表时打印更多细节，使用`-v`或`–vv`标志。这些标志称为详细（`v`），它将在终端上打印更多细节。例如，通过使用详细，您可以打印更多细节，如文件权限、所有者组、修改日期等。

例如：

```
$ tar -tvvf archive.tar
drwxr-xr-x slynux/slynux     0 2010-08-06 09:31 yy/
drwxr-xr-x slynux/slynux     0 2010-08-06 09:39 yy/usr/
drwxr-xr-x slynux/slynux     0 2010-08-06 09:31 yy/usr/lib64/

```

### 从存档中提取文件和文件夹

以下命令将存档的内容提取到当前目录：

```
$ tar -xf archive.tar

```

`-x`选项代表提取。

当使用`–x`时，`tar`命令将存档的内容提取到当前目录。我们还可以使用`–C`标志指定需要提取文件的目录，如下所示：

```
$ tar -xf archive.tar -C /path/to/extraction_directory

```

该命令将归档的内容提取到指定目录中。它提取归档的全部内容。我们也可以通过将它们指定为命令参数来仅提取一些文件：

```
$ tar -xvf file.tar file1 file4

```

上面的命令仅提取`file1`和`file4`，并忽略归档中的其他文件。

### 使用 tar 的 stdin 和 stdout

在归档时，我们可以指定`stdout`作为输出文件，以便通过管道出现的另一个命令可以将其读取为`stdin`，然后执行一些处理或提取归档。

这对于通过安全外壳（SSH）连接传输数据很有帮助（在网络上）。例如：

```
$ mkdir ~/destination
$ tar -cf - file1 file2 file3 | tar -xvf -  -C ~/destination

```

在上面的例子中，`file1`，`file2`和`file3`被合并成一个 tarball，然后提取到`~/destination`。在这个命令中：

+   `-f`指定`stdout`作为归档文件（当使用`-c`选项时）

+   `-f`指定`stdin`作为提取文件（当使用`-x`选项时）

### 连接两个归档

我们可以使用`-A`选项轻松合并多个 tar 文件。

假设我们有两个 tarballs：`file1.tar`和`file2.tar`。我们可以将`file2.tar`的内容合并到`file1.tar`中，如下所示：

```
$ tar -Af file1.tar file2.tar

```

通过列出内容来验证它：

```
$ tar -tvf file1.tar

```

### 使用时间戳检查更新归档中的文件

追加选项将任何给定的文件追加到归档中。如果在归档中有相同的文件要追加，它将追加该文件，并且归档将包含重复文件。我们可以使用更新选项`-u`来指定仅追加比归档中具有相同名称的文件更新的文件。

```
$ tar -tf archive.tar
filea
fileb
filec

```

该命令列出归档中的文件。

为了仅在`filea`的修改时间比`archive.tar`中的`filea`更新时追加`filea`，使用：

```
$ tar -uvvf archive.tar filea

```

如果归档外的`filea`的版本和`archive.tar`中的`filea`具有相同的时间戳，则不会发生任何事情。

使用`touch`命令修改文件时间戳，然后再次尝试`tar`命令：

```
$ tar -uvvf archive.tar filea
-rw-r--r-- slynux/slynux     0 2010-08-14 17:53 filea

```

由于其时间戳比归档中的时间戳更新，因此文件被追加。

### 比较归档和文件系统中的文件

有时候知道归档中的文件和文件系统中具有相同文件名的文件是否相同或包含任何差异是有用的。`–d`标志可用于打印差异：

```
$ tar -df archive.tar filename1 filename2 ...

```

例如：

```
$ tar -df archive.tar afile bfile
afile: Mod time differs
afile: Size differs

```

### 从归档中删除文件

我们可以使用`–delete`选项从给定的归档中删除文件。例如：

```
$ tar -f archive.tar --delete file1 file2 ..

```

让我们看另一个例子：

```
$ tar -tf archive.tar
filea
fileb
filec

```

或者，我们也可以使用以下语法：

```
$ tar --delete --file archive.tar [FILE LIST]

```

例如：

```
$ tar --delete --file archive.tar filea
$ tar -tf archive.tar
fileb
filec

```

### 使用 tar 归档进行压缩

`tar`命令只对文件进行归档，不对其进行压缩。因此，大多数人在处理 tarballs 时通常会添加某种形式的压缩。这显着减小了文件的大小。Tarballs 通常被压缩成以下格式之一：

+   `file.tar.gz`

+   `file.tar.bz2`

+   `file.tar.lzma`

+   `file.tar.lzo`

不同的`tar`标志用于指定不同的压缩格式。

+   `-j`用于 bunzip2

+   `-z`用于 gzip

+   `--lzma`用于 lzma

它们在以下特定于压缩的配方中有解释。

可以使用压缩格式而不明确指定特殊选项。`tar`可以通过查看输出或输入文件名的给定扩展名来进行压缩。为了使`tar`通过查看扩展名自动支持压缩，请使用`-a`或`--auto-compress`与`tar`。

### 从归档中排除一组文件

可以通过指定模式来排除一组文件不进行归档。使用`--exclude [PATTERN]`来排除与通配符模式匹配的文件。

例如，要排除所有`.txt`文件不进行归档，请使用：

```
$ tar -cf arch.tar * --exclude "*.txt"

```

### 提示

请注意，模式应该用双引号括起来。

还可以使用`-X`标志排除列表文件中提供的文件列表，如下所示：

```
$ cat list
filea
fileb

$ tar -cf arch.tar * -X list

```

现在排除了`filea`和`fileb`不进行归档。

### 排除版本控制目录

我们通常使用 tarballs 来分发源代码。大多数源代码是使用诸如 subversion、Git、mercurial、cvs 等版本控制系统进行维护的。版本控制下的代码目录将包含用于管理版本的特殊目录，如`.svn`或`.git`。但是，这些目录对代码本身并不需要，因此应该从源代码的 tarball 中删除。

为了在归档时排除与版本控制相关的文件和目录，请使用`tar`的`--exclude-vcs`选项。例如：

```
$ tar --exclude-vcs -czvvf source_code.tar.gz eye_of_gnome_svn

```

### 打印总字节数

如果我们可以打印复制到归档中的总字节数，有时会很有用。通过使用`--totals`选项在归档后打印复制的总字节数，如下所示：

```
$ tar -cf arc.tar * --exclude "*.txt" --totals
Total bytes written: 20480 (20KiB, 12MiB/s)

```

## 另请参阅

+   *使用 gunzip（gzip）进行压缩*，解释了 gzip 命令

+   *使用 bunzip（bzip2）进行压缩*，解释了 bzip2 命令

+   *使用 lzma 进行压缩*，解释了 lzma 命令

# 使用 cpio 进行归档

**cpio**是另一种类似于`tar`的归档格式。它用于将文件和目录存储在具有权限、所有权等属性的文件中。但是它并不像`tar`那样常用。然而，`cpio`似乎被用于 RPM 软件包归档、Linux 内核的 initramfs 文件等。本文将提供`cpio`的最小使用示例。

## 如何做...

`cpio`通过`stdin`接受输入文件名，并将归档写入`stdout`。我们必须将`stdout`重定向到文件以接收输出的`cpio`文件，如下所示：

创建测试文件：

```
$ touch file1 file2 file3

```

我们可以将测试文件归档如下：

```
$ echo file1 file2 file3 | cpio -ov > archive.cpio

```

在此命令中：

+   `-o`指定输出

+   `-v`用于打印已归档文件的列表

### 注意

通过使用`cpio`，我们还可以使用文件的绝对路径进行归档。`/usr/somedir`是一个绝对路径，因为它包含了从根目录(`/`)开始的完整路径。

相对路径不会以`/`开头，但它从当前目录开始。例如，`test/file`表示有一个名为`test`的目录，`file`在`test`目录内。

在提取时，`cpio`提取到绝对路径本身。但是在`tar`中，它会删除绝对路径中的`/`，并将其转换为相对路径。

为了列出`cpio`归档中的文件，请使用以下命令：

```
$ cpio -it < archive.cpio

```

此命令将列出给定`cpio`归档中的所有文件。它从`stdin`读取文件。在此命令中：

+   `-i`用于指定输入

+   `-t`用于列出

为了从`cpio`归档中提取文件，请使用：

```
$ cpio -id < archive.cpio

```

这里，`-d`用于提取。

它会在不提示的情况下覆盖文件。如果归档中存在绝对路径文件，它将替换该路径下的文件。它不会像`tar`那样在当前目录中提取文件。

# 使用 gunzip（gzip）进行压缩

**gzip**是 GNU/Linux 平台上常用的压缩格式。可用的实用程序包括`gzip`、`gunzip`和`zcat`，用于处理 gzip 压缩文件类型。`gzip`只能应用于文件。它不能归档目录和多个文件。因此我们使用`tar`归档并用`gzip`压缩。当多个文件作为输入时，它将产生多个单独压缩（`.gz`）文件。让我们看看如何使用`gzip`。

## 如何做...

为了使用`gzip`压缩文件，请使用以下命令：

```
$ gzip filename

$ ls
filename.gz

```

然后它将删除该文件并生成名为`filename.gz`的压缩文件。

提取`gzip`压缩文件如下：

```
$ gunzip filename.gz

```

它将删除`filename.gz`并生成`filename.gz`的未压缩版本。

为了列出压缩文件的属性，请使用：

```
$ gzip -l test.txt.gz
compressed        uncompressed  ratio uncompressed_name
 35                   6        -33.3% test.txt

```

`gzip`命令可以从`stdin`读取文件，并将压缩文件写入`stdout`。

从`stdin`读取并输出到`stdout`如下：

```
$ cat file | gzip -c > file.gz

```

`-c`选项用于指定输出到`stdout`。

我们可以为`gzip`指定压缩级别。使用`--fast`或`--best`选项分别提供低和高的压缩比。

## 还有更多...

`gzip`命令通常与其他命令一起使用。它还有高级选项来指定压缩比。让我们看看如何使用这些功能。

### 使用 tarball 的 gzip

我们通常使用`gzip`与 tarballs。可以通过在归档和提取时传递`-z`选项给`tar`命令来压缩 tarball。

您可以使用以下方法创建 gzipped tarballs：

+   **方法-1**

```
$ tar -czvvf archive.tar.gz [FILES]

```

或：

```
$ tar -cavvf archive.tar.gz [FILES]

```

`-a`选项指定应自动从扩展名检测压缩格式。

+   **方法-2**

首先，创建一个 tarball：

```
$ tar -cvvf archive.tar [FILES]

```

在打包后进行压缩如下：

```
$ gzip archive.tar

```

如果有许多文件（几百个）需要在一个 tarball 中进行归档并进行压缩，我们使用方法-2 并进行少量更改。使用`tar`将许多文件作为命令参数的问题是它只能从命令行接受有限数量的文件。为了解决这个问题，我们可以使用循环逐个添加文件并使用附加选项（`-r`）创建一个`tar`文件，如下所示：

```
FILE_LIST="file1  file2  file3  file4  file5"

for f in $FILE_LIST;
do
tar -rvf archive.tar $f 
done

gzip archive.tar
```

为了提取一个 gzipped tarball，使用以下命令：

+   -x 用于提取

+   `-z`用于 gzip 规范

或：

```
$ tar -xavvf archive.tar.gz -C extract_directory

```

在上述命令中，使用`-a`选项自动检测压缩格式。

### zcat-读取 gzipped 文件而不解压

`zcat`是一个命令，可用于从`.gz`文件中转储提取的文件到`stdout`，而无需手动提取它。`.gz`文件仍然与以前一样，但它将提取的文件转储到`stdout`，如下所示：

```
$ ls
test.gz

$ zcat test.gz
A test file
# file test contains a line "A test file"

$ ls
test.gz

```

### 压缩比

我们可以指定压缩比，可在 1 到 9 的范围内使用，其中：

+   1 是最低的，但速度最快

+   9 是最好的，但速度最慢

您还可以在之间指定比率，如下所示：

```
$ gzip -9 test.img

```

这将将文件压缩到最大。

## 另请参阅

+   *使用 tar 进行归档*，解释了 tar 命令

# 使用 bunzip（bzip）进行压缩

**bunzip2**是另一种与`gzip`非常相似的压缩技术。`bzip2`通常比`gzip`产生更小（更压缩）的文件。它随所有 Linux 发行版一起提供。让我们看看如何使用`bzip2`。

## 如何做...

为了使用`bzip2`进行压缩，使用：

```
$ bzip2 filename
$ ls
filename.bz2

```

然后它将删除文件并生成一个名为`filename.bzip2`的压缩文件。

提取一个 bzipped 文件如下：

```
$ bunzip2 filename.bz2

```

它将删除`filename.bz2`并产生一个未压缩版本的`filename`。

`bzip2`可以从`stdin`读取文件，并将压缩文件写入`stdout`。

为了从`stdin`读取并作为`stdout`读取，请使用：

```
$ cat file | bzip2 -c > file.tar.bz2

```

`-c`用于指定输出到`stdout`。

我们通常使用`bzip2`与 tarballs。可以通过在归档和提取时传递`-j`选项给`tar`命令来压缩 tarball。

可以通过以下方法创建一个 bzipped tarball：

+   **方法-1**

```
$ tar -cjvvf archive.tar.bz2 [FILES]

```

或：

```
$ tar -cavvf archive.tar.bz2 [FILES]

```

`-a`选项指定自动从扩展名检测压缩格式。

+   **方法-2**

首先创建 tarball：

```
$ tar -cvvf archive.tar [FILES]

```

在 tarball 后进行压缩：

```
$ bzip2 archive.tar

```

如果我们需要将数百个文件添加到存档中，则上述命令可能会失败。要解决此问题，请使用循环逐个使用`-r`选项将文件附加到存档中。请参阅食谱中的类似部分，*使用 gunzip（gzip）进行压缩*。

提取一个 bzipped tarball 如下：

```
$ tar -xjvvf archive.tar.bz2 -C extract_directory

```

在这个命令中：

+   `-x`用于提取

+   `-j`是用于`bzip2`规范

+   `-C`用于指定要提取文件的目录

或者，您可以使用以下命令：

```
$ tar -xavvf archive.tar.bz2 -C extract_directory

```

`-a`将自动检测压缩格式。

## 还有更多...

bunzip 有几个附加选项来执行不同的功能。让我们浏览其中的一些。

### 保留输入文件而不删除它们

在使用`bzip2`或`bunzip2`时，它将删除输入文件并生成一个压缩的输出文件。但是我们可以使用`-k`选项防止它删除输入文件。

例如：

```
$ bunzip2 test.bz2 -k
$ ls
test test.bz2

```

### 压缩比

我们可以指定压缩比，可在 1 到 9 的范围内使用（其中 1 是最少压缩，但速度快，9 是最高可能的压缩，但要慢得多）。

例如：

```
$ bzip2 -9 test.img

```

此命令提供最大压缩。

## 另请参阅

+   *使用 tar 进行归档*，解释了 tar 命令

# 使用 lzma 进行压缩

**lzma**与`gzip`或`bzip2`相比相对较新。`lzma`的压缩率比`gzip`或`bzip2`更高。由于大多数 Linux 发行版上没有预安装`lzma`，您可能需要使用软件包管理器进行安装。

## 如何做到...

为了使用`lzma`进行压缩，请使用以下命令：

```
$ lzma filename
$ ls
filename.lzma

```

这将删除文件并生成名为`filename.lzma`的压缩文件。

要提取`lzma`文件，请使用：

```
$ unlzma filename.lzma

```

这将删除`filename.lzma`并生成文件的未压缩版本。

`lzma`命令还可以从`stdin`读取文件并将压缩文件写入`stdout`。

为了从`stdin`读取并作为`stdout`读取，请使用：

```
$ cat file | lzma -c > file.lzma

```

`-c`用于指定输出到`stdout`。

我们通常使用`lzma`与 tarballs。可以通过在归档和提取时传递`--lzma`选项给`tar`命令来压缩 tarball。

有两种方法可以创建`lzma` tarball：

+   **方法-1**

```
$ tar -cvvf --lzma archive.tar.lzma [FILES]

```

或者：

```
$ tar -cavvf archive.tar.lzma [FILES]

```

`-a`选项指定自动从扩展名中检测压缩格式。

+   **方法-2**

首先，创建 tarball：

```
$ tar -cvvf archive.tar [FILES]

```

在 tarball 后进行压缩：

```
$ lzma archive.tar

```

如果我们需要将数百个文件添加到存档中，则上述命令可能会失败。为了解决这个问题，使用循环使用`-r`选项逐个将文件附加到存档中。请参阅配方中的类似部分，*使用 gunzip（gzip）进行压缩*。

## 还有更多...

让我们看看与`lzma`实用程序相关的其他选项

### 提取 lzma tarball

为了将使用`lzma`压缩的 tarball 提取到指定目录，请使用：

```
$ tar -xvvf --lzma archive.tar.lzma -C extract_directory

```

在这个命令中，`-x`用于提取。`--lzma`指定使用`lzma`来解压缩生成的文件。

或者，我们也可以使用：

```
$ tar -xavvf archive.tar.lzma -C extract_directory

```

`-a`选项指定自动从扩展名中检测压缩格式。

### 保留输入文件而不删除它们

在使用`lzma`或`unlzma`时，它将删除输入文件并生成输出文件。但是我们可以使用`-k`选项防止删除输入文件并保留它们。例如：

```
$ lzma test.bz2 -k
$ ls
test.bz2.lzma

```

### 压缩比

我们可以指定压缩比，可在 1 到 9 的范围内选择（1 表示最小压缩，但速度快，9 表示最大可能的压缩，但速度慢）。

您还可以按照以下方式指定比率：

```
$ lzma -9 test.img

```

此命令将文件压缩到最大。

## 另请参阅

+   *使用 tar 进行归档*，解释了 tar 命令

# 使用 zip 进行归档和压缩

ZIP 是许多平台上常用的压缩格式。在 Linux 平台上，它不像`gzip`或`bzip2`那样常用，但是互联网上的文件通常以这种格式保存。

## 如何做到...

为了使用 ZIP 进行归档，使用以下语法：

```
$ zip archive_name.zip [SOURCE FILES/DIRS]

```

例如：

```
$ zip file.zip file

```

在这里，将生成`file.zip`文件。

递归存档目录和文件如下：

```
$ zip -r archive.zip folder1 file2

```

在这个命令中，`-r`用于指定递归。

与`lzma`，`gzip`或`bzip2`不同，`zip`在归档后不会删除源文件。`zip`在这方面类似于`tar`，但`zip`可以压缩`tar`无法压缩的文件。但是，`zip`也添加了压缩。

为了提取 ZIP 文件中的文件和文件夹，请使用：

```
$ unzip file.zip

```

它将提取文件而不删除`filename.zip`（不像`unlzma`或`gunzip`）。

为了使用文件系统中的新文件更新存档中的文件，请使用`-u`标志：

```
$ zip file.zip -u newfile

```

通过使用`-d`来从压缩存档中删除文件，如下所示：

```
$ zip -d arc.zip file.txt

```

为了列出存档中的文件，请使用：

```
$ unzip -l archive.zip

```

# squashfs-重压缩文件系统

**squashfs**是一种基于重压缩的只读文件系统，能够将 2 到 3GB 的数据压缩到 700MB 的文件中。您是否曾经想过 Linux Live CD 是如何工作的？当启动 Live CD 时，它加载完整的 Linux 环境。Linux Live CD 使用名为 squashfs 的只读压缩文件系统。它将根文件系统保留在一个压缩的文件系统文件中。它可以进行回环挂载并访问文件。因此，当进程需要一些文件时，它们会被解压缩并加载到 RAM 中并被使用。当构建自定义的实时操作系统或需要保持文件高度压缩并且无需完全提取文件时，了解 squashfs 可能是有用的。对于提取大型压缩文件，需要很长时间。但是，如果文件进行回环挂载，它将非常快，因为只有在出现文件请求时才会解压缩压缩文件的所需部分。在常规解压缩中，首先解压缩所有数据。让我们看看如何使用 squashfs。

## 准备工作

如果您有 Ubuntu CD，只需在`CDRom ROOT/casper/filesystem.squashfs`中找到`.squashfs`文件。`squashfs`内部使用压缩算法，如`gzip`和`lzma`。`squashfs`支持在所有最新的 Linux 发行版中都可用。但是，为了创建`squashfs`文件，需要从软件包管理器安装额外的软件包**squashfs-tools**。

## 如何做...

为了通过添加源目录和文件创建`squashfs`文件，请使用：

```
$ mksquashfs SOURCES compressedfs.squashfs

```

源可以是通配符、文件或文件夹路径。

例如：

```
$ sudo mksquashfs /etc test.squashfs
Parallel mksquashfs: Using 2 processors
Creating 4.0 filesystem on test.squashfs, block size 131072.
[=======================================] 1867/1867 100%

More details will be printed on terminal. They are limited to save space

```

为了将`squashfs`文件挂载到挂载点，使用回环挂载如下：

```
# mkdir /mnt/squash
# mount -o loop compressedfs.squashfs /mnt/squash

```

您可以通过访问`/mnt/squashfs`来复制内容。

## 还有更多...

可以通过指定附加参数来创建`squashfs`文件系统。让我们看看附加选项。

### 在创建 squashfs 文件时排除文件

在创建`squashfs`文件时，可以使用通配符指定要排除的文件或文件模式的列表。

通过使用`-e`选项，可以排除作为命令行参数指定的文件列表。例如：

```
$ sudo mksquashfs /etc test.squashfs -e /etc/passwd /etc/shadow

```

`-e`选项用于排除`passwd`和`shadow`文件。

也可以使用`-ef`指定要排除的文件列表。

```
$ cat excludelist
/etc/passwd
/etc/shadow

$ sudo mksquashfs /etc test.squashfs -ef excludelist

```

如果我们想在排除列表中支持通配符，请使用`-wildcard`作为参数。

# 加密工具和哈希

加密技术主要用于保护数据免受未经授权的访问。有许多可用的算法，我们使用一组常见的标准算法。在 Linux 环境中有一些可用的工具用于执行加密和解密。有时我们使用加密算法哈希来验证数据完整性。本节将介绍一些常用的加密工具和这些工具可以处理的一般算法。

## 如何做...

让我们看看如何使用诸如 crypt、gpg、base64、md5sum、sha1sum 和 openssl 等工具：

+   **crypt**

`crypt`命令是一个简单的加密实用程序，它从`stdin`获取文件和密码作为输入，并将加密数据输出到`stdout`。

```
$ crypt <input_file> output_file
Enter passphrase:

```

它将交互式地要求输入密码。我们也可以通过命令行参数提供密码。

```
$ crypt PASSPHRASE < input_file > encrypted_file

```

要解密文件，请使用：

```
$ crypt PASSPHRASE -d < encrypted_file > output_file

```

+   **gpg（GNU 隐私保护）**

gpg（GNU 隐私保护）是一种广泛使用的加密方案，用于通过密钥签名技术保护文件，使得只有认证目标才能访问数据。gpg 签名非常有名。gpg 的详细信息超出了本书的范围。在这里，我们可以学习如何加密和解密文件。

要使用`gpg`加密文件，请使用：

```
$ gpg -c filename

```

此命令交互式地读取密码并生成`filename.gpg`。

要解密`gpg`文件，请使用：

```
$ gpg filename.gpg

```

此命令读取密码并解密文件。

+   **Base64**

Base64 是一组类似的编码方案，通过将二进制数据转换为基 64 表示形式的 ASCII 字符串格式来表示二进制数据。`base64`命令可用于编码和解码 Base64 字符串。

为了将二进制文件编码为 Base64 格式，请使用：

```
$ base64 filename > outputfile

```

或：

```
$ cat file | base64 > outputfile

```

它可以从`stdin`读取。

按照以下方式解码 Base64 数据：

```
$ base64 -d file > outputfile

```

或：

```
$ cat base64_file | base64 -d > outputfile

```

+   **md5sum** 和 **sha1sum**

**md5sum** 和 **sha1sum** 是单向哈希算法，无法逆转为原始数据。通常用于验证数据的完整性或从给定数据生成唯一密钥。对于每个文件，它通过分析其内容生成一个唯一密钥。

```
$ md5sum file
8503063d5488c3080d4800ff50850dc9  file

$ sha1sum file
1ba02b66e2e557fede8f61b7df282cd0a27b816b  file

```

这些类型的哈希适合于存储密码。密码以其哈希形式存储。当用户要进行身份验证时，密码被读取并转换为哈希。然后将哈希与已存储的哈希进行比较。如果它们相同，密码得到验证并提供访问权限，否则拒绝。存储原始密码字符串是有风险的，并会暴露密码的安全风险。

+   **类似影子的哈希（盐哈希）**

让我们看看如何生成类似影子的盐哈希密码。

Linux 中的用户密码以其哈希形式存储在`/etc/shadow`文件中。`/etc/shadow`中的典型行看起来像这样：

```
test:$6$fG4eWdUi$ohTKOlEUzNk77.4S8MrYe07NTRV4M3LrJnZP9p.qc1bR5c.EcOruzPXfEu1uloBFUa18ENRH7F70zhodas3cR.:14790:0:99999:7:::
```

在这行中`$6$fG4eWdUi$ohTKOlEUzNk77.4S8MrYe07NTRV4M3LrJnZP9p.qc1bR5c.EcOruzPXfEu1uloBFUa18ENRH7F70zhodas3cR`是与其密码对应的影子哈希。

在某些情况下，我们可能需要编写关键的管理脚本，可能需要使用 shell 脚本手动编辑密码或添加用户。在这种情况下，我们必须生成一个影子密码字符串，并写一个类似上面的行到影子文件中。让我们看看如何使用`openssl`生成影子密码。

影子密码通常是盐密码。`SALT`是一个额外的字符串，用于混淆和加强加密。盐由随机位组成，用作生成密码的盐哈希的输入之一。

有关盐的更多细节，请参阅维基百科页面[`en.wikipedia.org/wiki/Salt_(cryptography)`](http://en.wikipedia.org/wiki/Salt_(cryptography))。

```
$ openssl passwd -1 -salt SALT_STRING PASSWORD
$1$SALT_STRING$323VkWkSLHuhbt1zkSsUG.

```

用随机字符串替换`SALT_STRING`，用要使用的密码替换`PASSWORD`。

# 使用 rsync 备份快照

备份数据是大多数系统管理员需要定期执行的操作。我们可能需要在 Web 服务器或远程位置备份数据。`rsync`是一个可以用于将文件和目录从一个位置同步到另一个位置的命令，同时最小化数据传输，使用文件差异计算和压缩。`rsync`相对于`cp`命令的优势在于`rsync`使用强大的差异算法。此外，它支持网络数据传输。在复制文件时，它会比较原始位置和目标位置的文件，并只复制更新的文件。它还支持压缩、加密等等。让我们看看如何使用`rsync`。

## 如何做到...

为了将源目录复制到目的地（创建镜像），使用以下命令：

```
$ rsync -av source_path destination_path

```

在这个命令中：

+   `-a`代表存档

+   `-v`（详细）在`stdout`上打印详细信息或进度

上述命令将递归地将所有文件从源路径复制到目标路径。我们可以指定远程或本地主机路径。

它可以是格式为`/home/slynux/data`，[slynux@192.168.0.6:/home/backups/data](http://slynux@192.168.0.6:/home/backups/data)，等等。

`/home/slynux/data`指定了在执行`rsync`命令的机器上的绝对路径。`slynux@192.168.0.6:/home/backups/data`指定了 IP 地址为`192.168.0.6`的机器上的路径为`/home/backups/data`，并以用户`slynux`登录。

为了将数据备份到远程服务器或主机，请使用：

```
$ rsync -av source_dir username@host:PATH

```

为了在目的地保持镜像，以规律的间隔运行相同的`rsync`命令。它只会将更改的文件复制到目的地。

从远程主机恢复数据到`localhost`如下：

```
$ rsync -av username@host:PATH destination

```

`rsync`命令使用 SSH 连接到另一台远程计算机。在格式[user@host](http://user@host)中提供远程计算机地址，其中 user 是用户名，host 是附加到远程计算机的 IP 地址或域名。`PATH`是需要复制数据的绝对路径地址。`rsync`将像往常一样要求用户密码以进行 SSH 逻辑。这可以通过使用 SSH 密钥来自动化（避免用户密码探测）。

确保远程计算机上安装并运行 OpenSSH。

通过网络传输时压缩数据可以显著优化传输速度。我们可以使用`rsync`选项`-z`来指定在通过网络传输时压缩数据。例如：

```
$ rsync -avz source destination

```

### 注意

对于 PATH 格式，如果我们在源路径的末尾使用`/`，`rsync`将把指定在`source_path`中的末尾目录的内容复制到目的地。

如果源路径末尾没有`/`，`rsync`将复制该末尾目录本身到目的地。

例如，以下命令复制了`test`目录的内容：

```
$ rsync -av /home/test/ /home/backups

```

以下命令将`test`目录复制到目的地：

```
$ rsync -av /home/test /home/backups

```

### 注意

如果`destination_path`末尾有`/`，`rsync`将把源复制到目的地目录。

如果目的地路径末尾没有使用`/`，`rsync`将在目的地路径的末尾创建一个文件夹，该文件夹的名称与源目录类似，并将源复制到该目录中。

例如：

```
$ rsync -av /home/test /home/backups/

```

此命令将源（`/home/test`）复制到名为`backups`的现有文件夹。

```
$ rsync -av /home/test /home/backups

```

此命令通过创建目录将源（`/home/test`）复制到名为`backups`的目录中。

## 还有更多...

`rsync`命令具有几个额外的功能，可以使用其命令行选项来指定。让我们逐个了解。

### 在使用 rsync 进行归档时排除文件

有些文件在归档到远程位置时不需要更新。可以告诉`rsync`从当前操作中排除某些文件。文件可以通过两个选项来排除：

```
--exclude PATTERN
```

我们可以指定要排除的文件的通配符模式。例如：

```
$ rsync -avz /home/code/some_code /mnt/disk/backup/code --exclude "*.txt"

```

此命令排除了`.txt`文件的备份。

或者，我们可以通过提供一个文件列表来指定要排除的文件。

使用`--exclude-from FILEPATH`。

### 在更新 rsync 备份时删除不存在的文件

我们将文件存档为 tarball 并将 tarball 传输到远程备份位置。当我们需要更新备份数据时，我们再次创建一个 TAR 文件并将文件传输到备份位置。默认情况下，如果目的地不存在源文件，`rsync`不会从目的地删除文件。为了从目的地删除在源文件中不存在的文件，请使用`rsync --delete`选项：

```
$ rsync -avz SOURCE DESTINATION --delete

```

### 在间隔时间安排备份

您可以创建一个 cron 作业以规律的间隔安排备份。

示例如下：

```
$ crontab -e

```

添加以下行：

```
0 */10 * * * rsync -avz /home/code user@IP_ADDRESS:/home/backups

```

上述`crontab`条目安排每 10 小时执行一次`rsync`。

`*/10`是`crontab`语法的小时位置。`/10`指定每 10 小时执行一次备份。如果`*/10`写在分钟位置，它将每 10 分钟执行一次。

查看第九章中的*Scheduling with cron*配方，了解如何配置`crontab`。

# 基于 Git 的版本控制备份

人们在备份数据时使用不同的策略。差异备份比将整个源目录的副本复制到目标备份目录更有效，使用日期或当天时间的版本号。这会造成空间的浪费。我们只需要复制从第二次备份发生以来发生的文件更改。这称为增量备份。我们可以使用`rsync`等工具手动创建增量备份。但是恢复这种备份可能会很困难。保持和恢复更改的最佳方法是使用版本控制系统。它们在软件开发和代码维护中被广泛使用，因为编码经常发生变化。Git（GNU it）是一个非常著名且最有效的版本控制系统。让我们在非编程环境中使用 Git 备份常规文件。Git 可以通过您的发行版软件包管理器安装。它是由 Linus Torvalds 编写的。

## 准备工作

这是问题陈述：

我们有一个包含多个文件和子目录的目录。我们需要跟踪目录内容发生的更改并对其进行备份。如果数据损坏或丢失，我们必须能够恢复该数据的以前副本。我们需要定期将数据备份到远程机器。我们还需要在同一台机器（本地主机）的不同位置进行备份。让我们看看如何使用 Git 来实现它。

## 如何做…

在要备份的目录中使用：

```
$ cd /home/data/source

```

让源目录被跟踪。

设置并初始化远程备份目录。在远程机器上，创建备份目标目录：

```
$ mkdir -p /home/backups/backup.git

$ cd /home/backups/backup.git

$ git init --bare

```

以下步骤需要在源主机机器上执行：

1.  在源主机机器上将用户详细信息添加到 Git 中：

```
$ git config --global user.name  "Sarath Lakshman"
#Set user name to "Sarath Lakshman"

$ git config --global user.email slynux@slynux.com
# Set email to slynux@slynux.com

```

从主机机器初始化要备份的源目录。在要备份其文件的主机机器中的源目录中，执行以下命令：

```
$ git init
Initialized empty Git repository in /home/backups/backup.git/
# Initialize git repository

$ git commit --allow-empty -am "Init"
[master (root-commit) b595488] Init

```

1.  在源目录中，执行以下命令以添加远程 git 目录并同步备份：

```
$ git remote add origin user@remotehost:/home/backups/backup.git

$ git push origin master
Counting objects: 2, done.
Writing objects: 100% (2/2), 153 bytes, done.
Total 2 (delta 0), reused 0 (delta 0)
To user@remotehost:/home/backups/backup.git
 * [new branch]      master -> master

```

1.  添加或删除 Git 跟踪的文件。

以下命令将当前目录中的所有文件和文件夹添加到备份列表中：

```
$ git add *

```

我们可以有条件地将某些文件添加到备份列表中，方法如下：

```
$ git add *.txt
$ git add *.py

```

通过使用以下命令，我们可以删除不需要跟踪的文件和文件夹：

```
$ git rm file

```

它可以是一个文件夹，甚至是一个通配符，如下所示：

```
$ git rm *.txt

```

1.  检查点或标记备份点。

我们可以使用以下命令为备份标记检查点并附上消息：

```
$ git commit -m "Commit Message"

```

我们需要定期更新远程位置的备份。因此，设置一个 cron 作业（例如，每五个小时备份一次）。

创建包含以下行的 crontab 条目文件：

```
0 */5 * * *  /home/data/backup.sh

```

创建脚本`/home/data/backup.sh`如下：

```
#!/bin/ bash
cd /home/data/source
git add .
git commit -am "Commit - @ $(date)"
git push
```

现在我们已经设置好了备份系统。

1.  使用 Git 恢复数据。

为了查看所有备份版本，请使用：

```
$ git log

```

通过忽略任何最近的更改，将当前目录更新到上次备份。

+   要恢复到任何以前的状态或版本，请查看提交 ID，这是一个 32 个字符的十六进制字符串。使用提交 ID 和`git checkout`。

+   对于提交 ID 3131f9661ec1739f72c213ec5769bc0abefa85a9，它将是：

```
$ git checkout 3131f9661ec1739f72c213ec5769bc0abefa85a9
$ git commit -am "Restore @ $(date) commit ID: 3131f9661ec1739f72c213ec5769bc0abefa85a9"
$ git push

```

+   为了再次查看版本的详细信息，请使用：

```
$ git log

```

如果工作目录由于某些问题而损坏，我们需要使用远程位置的备份来修复目录。

然后我们可以按以下方式从远程位置重新创建内容：

```
$ git clone user@remotehost:/home/backups/backup.git

```

这将创建一个包含所有内容的目录备份。

# 使用 dd 克隆硬盘和磁盘

在处理硬盘和分区时，我们可能需要创建副本或备份完整分区，而不是复制所有内容（不仅是硬盘分区，还包括复制整个硬盘而不丢失任何信息，如引导记录、分区表等）。在这种情况下，我们可以使用`dd`命令。它可以用于克隆任何类型的磁盘，如硬盘、闪存驱动器、CD、DVD、软盘等。

## 准备工作

`dd`命令扩展到数据定义。由于不正确的使用会导致数据丢失，因此它被昵称为“数据销毁者”。在使用参数顺序时要小心。错误的参数可能导致整个数据丢失或变得无用。`dd`基本上是一个比特流复制器，它将整个比特流从磁盘复制到文件或从文件复制到磁盘。让我们看看如何使用`dd`。

## 如何做...

`dd`的语法如下：

```
$ dd if=SOURCE of=TARGET bs=BLOCK_SIZE count=COUNT

```

在这个命令中：

+   `if`代表输入文件或输入设备路径

+   `of`代表目标文件或目标设备路径

+   `bs`代表块大小（通常以 2 的幂给出，例如 512、1024、2048 等）。`COUNT`是要复制的块数（一个整数）。

总字节数=块大小*计数

`bs`和`count`是可选的。

通过指定`COUNT`，我们可以限制从输入文件复制到目标的字节数。如果未指定`COUNT`，`dd`将从输入文件复制，直到达到文件的结尾（EOF）标记。

为了将分区复制到文件中使用：

```
# dd if=/dev/sda1 of=sda1_partition.img

```

这里`/dev/sda1`是分区的设备路径。

使用备份还原分区如下：

```
# dd if=sda1_partition.img of=/dev/sda1

```

您应该小心处理参数`if`和`of`。不正确的使用可能会导致数据丢失。

通过将设备路径`/dev/sda1`更改为适当的设备路径，可以复制或还原任何磁盘。

为了永久删除分区中的所有数据，我们可以使用以下命令使`dd`将零写入分区：

```
# dd if=/dev/zero of=/dev/sda1

```

`/dev/zero`是一个字符设备。它总是返回无限的零'\0'字符。

将一个硬盘克隆到另一个相同大小的硬盘如下：

```
# dd if=/dev/sda  of=/dev/sdb

```

这里`/dev/sdb`是第二个硬盘。

为了使用 CD ROM（ISO 文件）的映像文件使用：

```
# dd if=/dev/cdrom of=cdrom.iso

```

## 还有更多...

当在使用`dd`生成的文件中创建文件系统时，我们可以将其挂载到挂载点。让我们看看如何处理它。

### 挂载映像文件

使用`dd`创建的任何文件映像都可以使用回环方法挂载。使用`mount`命令和`-o loop`。

```
# mkdir /mnt/mount_point
# mount -o loop file.img /mnt/mount_point

```

现在我们可以通过位置`/mnt/mount_point`访问映像文件的内容。

## 参见

+   *创建 ISO 文件，混合 ISO* 第三章解释了如何使用 dd 从 CD 创建 ISO 文件
