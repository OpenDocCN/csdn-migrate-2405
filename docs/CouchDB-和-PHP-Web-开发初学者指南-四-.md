# CouchDB 和 PHP Web 开发初学者指南（四）

> 原文：[`zh.annas-archive.org/md5/175c6f9b2383dfb7631db24032548544`](https://zh.annas-archive.org/md5/175c6f9b2383dfb7631db24032548544)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 附录 A. 小测验 — 答案

# 第二章，设置开发环境

| 1 | 当我们使用默认的 Apache 安装进行 Web 开发时，默认的工作目录在哪里？ | `[/Library/WebServer/Documents]` |
| --- | --- | --- |
| 2 | 为了在 CouchDB 中使用我们的本地开发环境，我们需要确保两个服务正在运行。它们是什么，如何在终端中使它们运行？ |

+   [Apache]

sudo apachetl start

+   [CouchDB]

**couchdb -b**

|

| 3 | 你使用什么命令行语句向 CouchDB 发出`Get`请求？ | **curl http://127.0.0.1:5984/** |
| --- | --- | --- |

# 第三章，使用 CouchDB 和 Futon 入门

| 1 | 根据[`couchdb.apache.org/?`](http://couchdb.apache.org/?)，CouchDB 的定义的第一句是什么？ | CouchDB 是一个文档数据库服务器，可通过 RESTful JSON API 访问。 |
| --- | --- | --- |
| 2 | HTTP 使用的四个动词是什么，每个动词如何匹配 CRUD？ |

+   `[GET -> 读取]`

+   `[PUT -> 创建，更新]`

+   `[POST -> 创建]`

+   `[DELETE -> 删除]`

|

| 3 | 访问 Futon 的 URL 是什么？ | `http://localhost:5984/_utils/` |
| --- | --- | --- |
| 4 | 对于 CouchDB 来说，什么是 Admin Party 这个术语，如何使 CouchDB 退出这种模式？ | Admin Party 是 CouchDB 的默认状态，其中没有服务器管理员，因此用户没有任何限制。通过点击**Fix This**并添加服务器管理员，我们可以使 CouchDB 退出这种模式。 |
| 5 | 你如何通过命令行为安全数据库验证用户？ | 在 URL 前面添加`username:password@` |
