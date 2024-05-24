# React 和 Firebase 无服务器 Web 应用（三）

> 原文：[`zh.annas-archive.org/md5/330929BAB4D0F44DAFAC93D065193C41`](https://zh.annas-archive.org/md5/330929BAB4D0F44DAFAC93D065193C41)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：Firebase 安全和规则

在上一章中，我们看到了如何在应用程序中整合访问管理以保护它免受未经授权的访问，这实质上是应用程序级别的安全性。然而，如果我们的数据库没有得到保护呢？嗯，在这种情况下，数据可能会被未经授权的用户或甚至经过授权的用户（如数据库管理员）滥用，这会导致业务损失，有时甚至会引发法律诉讼。

数据安全始终是一个主要关注点，特别是当它托管在云服务器上时。我们必须保护我们的数据免受完整性、可用性和机密性的妥协。无论您使用的是关系型数据库管理系统，如 MySQL 或 MSSQL，还是 NoSQL，如 MongoDB 或 Firebase 实时数据库；所有这些数据库都必须通过限制对数据的访问来进行保护。在本章中，我们将简要介绍常见的数据库安全风险以及预防此类威胁的清单。我们还将看到 Firebase 实时数据库的安全部分和 Firebase 实时数据库规则语言。

以下是本章将讨论的主题列表：

+   常见数据库安全风险和预防措施概述

+   Firebase 安全概述

+   Firebase 实时数据库规则概述

+   Firebase 实时数据库规则的结构和定义

+   数据索引简介

+   数据库备份和恢复

让我们从威胁的安全风险和预防开始。

# 安全风险和预防

数据库是任何组织的核心，因为它们包含客户数据和机密业务数据，因此它们经常成为黑客的目标。在过去几年中已经确定了一些常见的威胁，包括以下内容：

+   未经授权或意外活动

+   恶意软件感染

+   数据库服务器的物理损坏

+   由于无效数据而导致数据损坏

+   性能下降

为了防止这些风险，需要遵循许多协议或安全标准：

1.  访问控制：包括身份验证和授权。所有数据库系统都提供访问控制机制，例如使用用户名和密码进行身份验证。同时，在某些数据库中，设置它并不是强制性的，因此有时人们不启用它，使数据库不安全。同样，在所有数据库中，提供了基于角色的安全授权机制，以限制用户对某些数据或数据库的访问。然而，有时人们会给予所有用户根或管理员访问权限，使数据对所有用户开放。

1.  审计：审计涉及监控所有用户执行的数据库活动，以增强安全性并保护数据。许多数据库平台包括内置的审计功能，允许您跟踪数据创建、删除或修改活动以及数据库使用情况，以便在早期检测到任何可疑活动。

1.  备份：备份旨在从较早的时间恢复数据，并在数据删除或数据损坏的情况下恢复数据。根据要求，备份过程可以是自动化的或手动的。理想情况下，应该是自动化的，以便可以定期进行备份。虽然至少应该有一些备份，但数据存储空间可能很大，这取决于数据/备份的大小。为了减小备份的大小，应在持久化之前对备份文件进行压缩。

1.  数据完整性控制：数据完整性是指数据库中存储的数据的一致性和准确性。数据验证是数据完整性的先决条件。许多关系数据库（RDBMS）通过约束（如主键和外键约束）强制数据完整性。在 NoSQL 的情况下，需要在数据库级别和应用程序级别进行数据验证，以确保数据完整性。

1.  应用程序级安全性：还需要应用程序级安全性，以防止任何不当的数据保存在数据库中。通常，开发人员在表单级别和业务级别进行验证，以确保他们在数据库中保存有效的数据。

1.  加密：加密个人数据（如社会安全号码）或金融数据（如信用卡信息）非常重要，以防止其被滥用。通常，使用 SSL 加密来加密客户端和服务器之间的连接，这实质上是网络级别的安全，以防止任何恶意攻击者阅读这些信息。

现在，让我们来检查 Firebase 中我们的数据有多安全。

# 您的 Firebase 有多安全？

Firebase 位于云存储上，因此人们很自然地会考虑它是否足够安全。然而，不用担心，因为 Firebase 提供了一个安全的架构和一套工具来管理应用程序的安全性。Firebase 托管在 SSL（安全套接字层）上，通常加密客户端和服务器之间的连接，从而防止在网络层发生任何数据窃取或篡改。Firebase 配备了基于表达式的规则语言，允许您通过配置来管理数据安全性。

Firebase 安全性主要是关于配置而不是约定，这样您的应用程序的安全相关逻辑就与业务逻辑分离开来。这样一来，您的应用程序就变得松散耦合。

在本章中，我们将学习有关 Firebase 实时数据库安全性和规则的内容。

# 实时数据库规则概述

Firebase 数据库规则允许您管理对数据库的读取和写入访问权限。它们还帮助您定义数据的验证方式，例如它是否具有有效的数据类型和格式。只有在您的规则允许的情况下，读取和写入请求才会被完成。默认情况下，您的规则被设置为只允许经过身份验证的用户完全读取和写入数据库。

Firebase 数据库规则具有类似 JavaScript 的语法，并分为四种类型：

| `.read` | 它确定用户何时允许读取数据。 |
| --- | --- |
| `.write` | 它确定用户何时允许写入数据。 |
| `.validate` | 它验证值是否格式正确，是否具有子属性以及其数据类型。 |
| `.indexOn` | 它确定子级是否存在索引以支持更快的查询和排序。 |

您可以从 Firebase 控制台的 Database || Rulestab 中访问和设置您的规则：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/cf48ed62-4bce-4f33-aa03-750add6b25ea.png)

Firebase 实时数据库安全性有三个步骤：

1.  用户认证

1.  用户授权-控制对数据的访问

1.  用户输入验证

# 认证

用户身份验证是保护应用程序免受未经授权访问的第一步。在第一步中识别用户自动意味着对他们可以访问和操作的数据的限制。在我们使用 Java、Microsoft.Net 或任何其他平台的后端技术的应用程序中，我们编写身份验证逻辑来限制对我们应用程序的访问。然而，由于 Firebase 广泛用于仅客户端应用程序，我们将没有后端工具的奢侈。幸运的是，Firebase 平台提供了一种身份验证机制—Firebase 身份验证—它内置了对常见身份验证机制的支持，如基于表单的身份验证、使用用户名和密码的 Google 和 Facebook 登录等。在第三章中，*使用 Firebase 进行身份验证*，以及第五章中，*用户配置文件和访问管理*，我们已经看到了如何实现 Firebase 身份验证。以下规则指定要访问数据库，用户必须经过身份验证。它还指定一旦用户经过身份验证，就可以访问数据库中的所有可用数据：

```jsx
{
  "rules": {
    ".read": "auth != null",
    ".write": "auth != null"
  }
}
```

# 授权

一旦用户经过身份验证，他们就可以访问数据库。但是，您需要对谁可以访问什么进行一些控制。不应该允许每个人读取/写入数据库中的所有数据。这就是授权出现的地方。Firebase 数据库规则允许您控制每个用户的访问权限。Firebase 安全规则是基于节点的，并由一个 JSON 对象管理，您可以在实时数据库控制台上编辑它，也可以使用 Firebase CLI：

```jsx
{
  "rules": {
        "users": { 
           ".read": "true",
           ".write": "false"
        }
  }
}
```

前面的规则确定所有用户都能够读取用户数据，但没有人能够对其进行写入。另外，请注意，必须将`rules`作为安全 JSON 对象中的第一个节点。

以下是指定用户私有数据的规则示例：

```jsx
{
  "rules": {
    "users": {
      "$uid": {
        ".read": "$uid === auth.uid",
        ".write": "$uid === auth.uid"
      }
    }
  }
}
```

现在，您可能会有一个问题，比如我们有嵌套的数据结构，规则将如何应用到该数据。为了回答这个问题，这里要记住的一点是，`.read`和`.write`规则**级联**，即授予对*父节点*的读取或写入访问权限总是授予对*所有子节点*的读取/写入访问权限。

父节点上的规则具有更高的优先级，因此它们将覆盖其子级别定义的规则。

Firebase 规则还提供了一些内置变量和函数，允许您访问 Firebase 身份验证信息，引用其他路径等。我们将在本章的后续部分详细检查这一点。

# 数据验证

如在介绍部分中所示，我们需要在将数据保存到数据库之前验证数据，以保持数据的完整性和正确性。Firebase 规则提供`.validate`表达式，如`.read`和`.write`来实现验证逻辑，例如字段的长度应该只有这么多个字符，或者它必须是字符串数据类型。

考虑这个例子：

```jsx
{
  "rules": {
        "users": { 
             "email": {
                    ".validate":  "newData.isString() && newData.val().length < 50"
              }
        }
  }
}
```

上述电子邮件字段的验证规则确定了电子邮件字段的值必须是字符串，其长度应小于 30 个字符。

重要的是要注意**验证规则不会级联**，因此为了允许写入，所有相关的验证规则必须评估为 true。

现在，我们已经对 Firebase 规则有了基本的了解，让我们深入了解规则配置。

# 规则定义和结构

Firebase 规则提供了可以在规则定义中使用的预定义变量：

| 名称 | 定义/用法 |
| --- | --- |
| `auth` | 它表示经过身份验证的用户的信息。对于未经身份验证的用户，它将为 null。它是一个包含 uid、token 和 provider 字段及相应值的对象。 |
| `$ variables` | 它表示通配符路径，用于引用动态生成的键和表示 ID。 |
| `root` | 它表示在应用给定数据库操作之前 Firebase 数据库中根路径的数据快照。 |
| `data` | 它表示给定数据库操作之前的数据快照。例如，在更新或写入的情况下，根代表原始数据快照，不包括更新或写入中的更改。 |
| `newData` | 它表示给定数据库操作之前的数据快照。然而，它包括现有数据以及新数据，其中包括给定数据操作操纵的数据。 |
| `now` | 它表示当前时间（以毫秒为单位）-自 1970 年 1 月 1 日（协调世界时午夜）以来经过的*秒数*。 |

在下一节中，我们将看看如何在我们的规则中使用这些预定义变量。

正如我们在授权部分看到的，我们需要看看规则如何适用于嵌套数据。一个经验法则是，我们需要根据数据库中数据的结构来构建规则。

我们将扩展我们在本书的第五章中开发的 HelpDesk 应用程序，*用户配置文件和访问管理*。

我们有以下的数据结构：

```jsx
"helpdesk" : {
    "tickets" : {
      "FlQefqueU2USLElL4vc5MoNUnu03" : {
        "-L4L1BLYiU-UQdE6lKA_" : {
          "comments" : "Need extra 4GB RAM in my system",
          "date" : "Fri Feb 02 2018 15:51:10 GMT+0530 (India Standard 
           Time)",
          "department" : "IT",
          "email" : "harmeet_15_1991@yahoo.com",
          "issueType" : "Hardware Request",
          "status" : "progress"
        }
      },
      "KEEyErkmP3YE1BagxSci0hF0g8H2" : {
        "-L4K01hUSDzPXTIXY9oU" : {
          "comments" : "Not able to access my email",
          "date" : "Fri Feb 02 2018 11:06:32 GMT+0530 (India Standard 
           Time)",
          "department" : "IT",
          "email" : "harmeetsingh090@gmail.com",
          "issueType" : "Email Related Issues",
          "status" : "progress"
        }
      },
      "all" : {
        "-L4K01hUSDzPXTIXY9oU" : {
          "comments" : "Not able to access my email",
          "date" : "Fri Feb 02 2018 11:06:32 GMT+0530 (India Standard 
           Time)",
          "department" : "IT",
          "email" : "harmeetsingh090@gmail.com",
          "issueType" : "Email Related Issues",
          "status" : "progress"
        },
        "-L4L1BLYiU-UQdE6lKA_" : {
          "comments" : "Need extra 4GB RAM in my system",
          "date" : "Fri Feb 02 2018 15:51:10 GMT+0530 (India Standard 
           Time)",
          "department" : "IT",
          "email" : "harmeet_15_1991@yahoo.com",
          "issueType" : "Hardware Request",
          "status" : "progress"
        }
      }
    }
  }
```

在这里，我们可以看到要使数据在用户级别上得到保护，只显示与已登录用户相关的工单，我们将它们存储在 userId 下，比如`FlQefqueU2USLElL4vc5MoNUnu03`和`KEEyErkmP3YE1BagxSci0hF0g8H2`，并且要向管理员显示所有工单，我们将它们存储在`all`下。然而，这并不是理想的解决方案，因为它有两个问题：数据是冗余的，并且要更新任何数据，我们将不得不在两个地方进行更新。幸运的是，我们可以直接在数据库中使用规则处理这种安全性。

我们将改变我们的数据，从数据中删除`all`节点。我们还将在`$userId`下添加一个变量来标识用户是否是管理员。所以它将看起来像这样：

```jsx
"helpdesk" : {
    "tickets" : {
      "FlQefqueU2USLElL4vc5MoNUnu03" : {
        "-L4L1BLYiU-UQdE6lKA_" : {
          "comments" : "Need extra 4GB RAM in my system",
          "date" : "Fri Feb 02 2018 15:51:10 GMT+0530 (India Standard 
           Time)",
          "department" : "IT",
          "email" : "harmeet_15_1991@yahoo.com",
          "issueType" : "Hardware Request",
          "status" : "progress"
        },
         "isAdmin": true
      },
      "KEEyErkmP3YE1BagxSci0hF0g8H2" : {
        "-L4K01hUSDzPXTIXY9oU" : {
          "comments" : "Not able to access my email",
          "date" : "Fri Feb 02 2018 11:06:32 GMT+0530 (India Standard 
           Time)",
          "department" : "IT",
          "email" : "harmeetsingh090@gmail.com",
          "issueType" : "Email Related Issues",
          "status" : "progress"
        },
        "isAdmin": false
      }
    }
  }
}
```

我们的规则将如下所示：

```jsx
{
  "rules": {
     "helpdesk": {
      "tickets": {
        ".read": "data.child(auth.uid).child('isAdmin').val()==true",
        ".write": "data.child(auth.uid).child('isAdmin').val()==true",
        "$uid": {
          ".read": "auth.uid == $uid",
          ".write": "auth.uid == $uid"
        }
      }
     }

  }
}
```

这些规则实质上施加了限制，如果用户是管理员，也就是`isAdmin`为 true，那么他们可以读取和写入所有数据。然而，其他用户只能读/写自己的数据。

在这里，我们还使用了预定义的变量 data，它代表了`write`操作之前的`DataSnapshot`。同样，我们可以使用`root`变量来引用根路径，`newData`来引用写操作后将存在的数据快照。

现在，如果你已经注意到，我们使用了`.child`，这实质上是用来引用任何子路径/属性的。在我们的规则中，我们正在检查在`$uid`下，`isAdmin`的值是否为 true，因为我们希望给管理员访问所有数据的权限。同样，我们可以在我们的规则中使用任何数据作为条件。

另一个重要的事情要注意的是，一旦我们在父级`tickets`上定义了`.read`和`.write`规则，我们就不再在`$uid`下检查`isAdmin`条件，因为**规则会级联**，所以一旦你授予管理员读/写权限，你就不需要在`$uid`级别重复这些条件。同时，重要的是要注意，在父位置定义规则是强制性的。如果我们不在父位置定义规则，即使子路径是可访问的，你的数据操作也会完全失败。

例如，在以下规则中，我们可以看到，尽管我们在票证级别拥有访问权限，但由于我们在`$uid`级别未定义规则，我们将无法访问数据：

```jsx
{
  "rules": {
     "helpdesk": {
      "tickets": {
        "$ticketId": {
          ".read": true,
          ".write": true
        }
      }
     }

  }
}
```

# 基于查询的规则

如前面的示例所示，规则不能用作过滤器。但是，有时我们需要根据某些条件或查询参数仅访问数据的子集。例如，假设我们需要仅从查询结果集中返回 1000 条记录中的前 100 条记录。我们可以通过使用**query.**表达式根据查询参数为您的结果集提供读取和写入访问权限：

```jsx
tickets: {
  ".read": "query.limitToFirst <= 100"
}
```

前面的代码将默认访问前 100 条按键排序的记录。如果要指定`orderByChild`，也可以这样做，如下所示：

```jsx
tickets: {
  ".read": "query.orderByChild == 'department' && query.limitToFirst <= 100"
}
```

确保在读取数据时，指定`orderByChild`，否则读取将失败。

# 数据索引

Firebase 允许您使用子键编写查询。为了提高查询性能，您可以使用`.indexOn`规则在这些键上定义索引。我们假设您已经知道索引的工作原理，因为几乎所有数据库系统都支持索引。

让我们举个例子来更好地理解这一点。假设在我们的 HelpDesk 系统中，我们经常按部门键订购票，并且我们正在使用`orderbyChild()`：

```jsx
{  "rules":  {
 "helpdesk": { "tickets":  {  ".indexOn":  ["department"]  }
      }  }  }
```

类似地，如果我们使用`orderByValue()`，我们可以有以下规则：

```jsx
".indexOn":  ".value"
```

# 备份

在本章的第一部分中，我们看到了管理数据备份的重要性。虽然您可以手动进行数据备份，但有可能会错过一些内容并丢失备份。幸运的是，Firebase 提供了自动备份服务，可以设置为每天自动备份数据和规则。请注意，此服务仅适用于 Blaze 计划用户，并且将按照标准费率收费。您可以查看[`firebase.google.com/pricing/`](https://firebase.google.com/pricing/)上提供的各种订阅计划。

# 设置

您可以从 Firebase 部分的实时数据库的备份选项卡设置数据库备份。设置向导将指导您完成配置自动备份的步骤。您的数据库备份活动将在每天的特定时间进行，而不会影响负载，并确保所有备份客户的最高可用性。

此外，您还可以在需要获取数据和规则的时间点快照时随时进行手动备份。

您的备份将存储在 Google Cloud Storage 中，这是 Google Cloud Platform 提供的对象存储服务。基本上，Google Cloud Storage 提供了类似计算机文件系统上的目录的存储桶，您的备份将存储在其中。因此，一旦设置完成，将创建一个具有权限的存储桶，您的 Firebase 可以在其中写入数据。我们将在第八章*Firebase 云存储*中详细了解 Google Cloud Storage 和 Firebase 云存储。

备份服务会自动使用 Gzip 压缩备份文件，从而减小整体备份大小，最终降低成本，同时最小化数据传输时间。压缩文件大小根据数据库中的数据而变化，但通常情况下，它会将整体文件大小减小到原始解压文件大小的 1/3。您可以根据需求启用或禁用 Gzip 压缩。

为了进一步节省成本，您还可以在存储桶上启用 30 天的生命周期策略来删除旧的备份；例如，30 天前的备份会自动被删除。

您可以通过执行以下命令行命令来解压缩您的 Gzipped JSON 文件，该命令使用默认情况下在 OS-X 和大多数 Linux 发行版上都可用的`gunzip`二进制文件：

```jsx
gunzip <DATABASE_NAME>.json.gz
```

文件名将根据以下命名约定生成。它将具有时间戳（ISO 8601 标准）：

```jsx
Database data: YYYY-MM-DDTHH:MM:SSZ_<DATABASE_NAME>_data.json
Database rules: YYYY-MM-DDTHH:MM:SSZ_<DATABASE_NAME>_rules.json
```

如果启用了 Gzip 压缩，文件名将附加一个`.gz`后缀。

考虑这个例子：

```jsx
 Database data: YYYY-MM-DDTHH:MM:SSZ_<DATABASE_NAME>_data.json.gz
Database rules: YYYY-MM-DDTHH:MM:SSZ_<DATABASE_NAME>_rules.json.gz
```

一旦您进行了备份，您可能会希望在某个时间点进行恢复。让我们看看如何从备份中恢复数据。

# 从备份中恢复

要从备份中恢复数据，首先从 Google Cloud Storage 下载备份文件，并根据前面的命令进行解压缩。一旦您有了 JSON 文件，您可以通过以下两种方式之一导入数据：

+   在 Firebase 控制台的数据库部分，您将找到一个导入 JSON 按钮，它将允许您上传文件。

+   您可以使用 CURL 命令：`curl 'https://<DATABASE_NAME>.firebaseio.com/.json?auth=<SECRET>&print=silent' -x PUT -d @<DATABASE_NAME>.json`。请注意，您需要分别用自己的值替换`DATABASE_NAME`和`SECRET`。您可以从数据库设置页面获取密钥。

# 总结

本章解释了数据面临的常见安全威胁，特别是当数据存储在云上时，以及我们如何保护我们的数据。它还解释了 Firebase 是安全的，只要我们通过在数据库中定义适当的规则并控制对数据的访问来正确管理安全性，我们就不必过多担心数据的安全性。

Firebase 托管在安全服务器层上，该层管理传输层的安全性。它还为您提供了一个强大而简单的规则引擎，可以配置以保护您的数据，并同时获得关注分离的好处——将安全逻辑与应用逻辑分离。

我们还详细学习了安全规则，以及如何使用类似于简单的 JavaScript 语法来定义它们。

在下一章中，我们将探讨 Firebase 云消息传递和云函数。


# 第七章：在 React 中使用 Firebase Cloud Messaging 和 Cloud Functions

在之前的章节中，我们探讨了一些 Firebase 产品，比如实时数据库、身份验证、Cloud Firestore 和 Cloud Storage。然而，我们还没有看到一些高级功能，比如实时消息传递和无服务器应用开发。现在我们准备好探索它们了，所以让我们讨论 Firebase 平台的另外两个产品：Firebase Cloud Messaging 和 Cloud Functions。Firebase Cloud Messaging 是一个消息平台，可以在不同平台（Android、iOS 和 Web）上免费发送消息。Cloud Functions 允许你拥有无服务器应用，这意味着你可以在没有服务器的情况下运行自定义应用逻辑。

以下是本章我们将重点关注的主题列表：

+   **Firebase Cloud Messaging**（**FCM**）的主要特点

+   JavaScript Web 应用的 Firebase 设置

+   客户端应用设置以接收通知

+   服务器设置以发送通知

+   Cloud Functions 的主要特点

+   为 Cloud Functions 设置 Firebase SDK

+   Cloud Function 的生命周期

+   触发函数

+   部署和执行函数

+   函数的终止

让我们先从 FCM 开始，然后我们将介绍 Cloud Functions。

# Firebase Cloud Messaging（FCM）

FCM 提供了一个平台，帮助你使用服务工作者实时向应用用户发送消息和通知。你可以免费跨不同平台发送数百亿条消息，包括 Android、iOS 和 Web（JavaScript）。你还可以安排消息的发送时间，立即或在将来。

FCM 实现中有两个主要组件：一个受信任的环境，包括一个应用服务器或 Cloud 函数来发送消息，以及一个 iOS、Android 或 Web（JavaScript）客户端应用来接收消息。

如果你了解**Google Cloud Messaging**（**GCM**），你可能会问 FCM 与 GCM 有何不同。对这个问题的答案是，FCM 是 GCM 的最新和改进版本。它继承了 GCM 的所有基础设施，并对简化客户端开发进行了改进。只是要注意，GCM 并没有被弃用，Google 仍在支持它。然而，新的客户端功能只会出现在 FCM 上，因此根据 Google 的建议，你应该从 GCM 升级到 FCM。

尽管它支持不同的平台，包括 Android、iOS 和 Web，但在本章中我们主要讨论 Web（JavaScript）。现在让我们来看看 FCM 的主要特点。

# FCM 的关键功能

GCM 的关键功能包括下行消息、上行消息和多功能消息。让我们在下一部分简要地看一下这些功能是什么。

# 发送下行消息

下行消息是代表客户端应用程序从服务器发送给用户的。FCM 消息可以分为两类：通知消息和数据消息。通知消息直接显示给用户。通知消息的一些示例是警报消息、聊天消息，或者通知客户端应用程序启动一些处理的消息备份。数据消息需要在客户端应用程序代码中处理。一些示例是聊天消息或任何特定于您的应用程序的消息。我们将在 FCM 消息的下一部分更多地讨论这些消息类型。

# 发送上行消息

上行消息通过 FCM 通道从设备发送回服务器。您可以通过可靠的 FCM 通道将确认、聊天消息和其他消息从设备发送回服务器。

# 多功能消息定位

FCM 非常灵活，允许您向单个设备、一组设备或所有订阅特定主题的订阅者发送消息。

# FCM 消息

使用 FCM，您可以向客户端发送两种类型的消息：通知消息和数据消息。使用 Firebase SDK 时，这两种消息的最大有效负载大小为 4 KB。但是，当您从 Firebase 控制台发送消息时，它会强制执行 1024 个字符的限制。

通知消息由 FCM SDK 自动处理，因为它们只是显示消息。当您希望 FCM 代表您的客户端应用程序显示通知时，可以使用通知消息。通知消息包含一组预定义的键，还可以包含可选的数据有效负载。

通知消息对象如下所示：

```jsx
{
  "message":{
    "token":"bk3RNwTe3H0:CI2k_HHwgIpoDKCIZvvDMExUdFQ3P1...",
    "notification":{
      "title":"This is an FCM notification message!",
      "body":"FCM message"
    }
  }
}
```

数据消息由客户端应用程序处理，并包含用户定义的键。它们如下所示：

```jsx
{
  "message":{
    "token":"bk3RNwTe3H0:CI2k_HHwgIpoDKCIZvvDMExUdFQ3P1...",
    "data":{
      "Name" : "MT",
      "Education" : "Ph.D."
    }
  }
}
```

我们将在接下来的部分看到什么是令牌。

# 为 Javascript Web 应用程序设置 Firebase

FCM 允许您在不同浏览器中的 Web 应用程序中接收通知消息，并支持服务工作者。服务工作者是在后台运行的浏览器脚本，提供离线数据功能、后台数据同步、推送通知等功能。服务工作者支持在以下浏览器中使用：

+   Chrome：50+

+   Firefox：44+

+   Opera Mobile：37+

使用服务工作者，人们可以进行一些恶意活动，比如过滤响应或劫持连接。为了避免这种情况，服务工作者只能在通过 HTTPS 提供的页面上使用。因此，如果您想使用 FCM，您将需要在服务器上拥有有效的 SSL 证书。请注意，在本地环境中，您不需要 SSL；它可以在本地主机上正常工作。

# 安装 Firebase 和 Firebase CLI

如果您要开始一个新的 React 项目，最简单的方法是使用 React Starter Kit 开始。您可以使用以下命令创建一个 React 项目，然后安装**firebase**和**firebase-tools**。如果这是一个现有的 React 和 Firebase 项目，您可以跳过安装步骤：

```jsx
npm install -g create-react-app
```

您可以使用以下命令安装 Firebase：

```jsx
npm install firebase --save
```

您还需要安装 Firebase CLI 以在服务器上运行您的项目。可以使用以下命令进行安装：

```jsx
npm install -g firebase-tools
```

现在，我们将使用 FCM 实现来扩展 Helpdesk 应用程序。

# 配置浏览器以接收消息

首先，您需要从[`developers.google.com/web/fundamentals/web-app-manifest/file`](https://developers.google.com/web/fundamentals/web-app-manifest/file)中添加一个 Web 应用程序清单到我们的项目中，并将以下内容添加到其中：

```jsx
{
  "gcm_sender_id": "103953800507"
}
```

它告诉浏览器允许 FCM 向此应用程序发送消息。`103953800507`的值是硬编码的，在任何您的应用程序中必须相同。Web 应用程序清单是一个简单的 JSON 文件，将包含与您的项目相关的配置元数据，例如您的应用程序的起始 URL 和应用程序图标详细信息。

我们在代码的根文件夹中创建了一个`manifest.json`文件，并将上述内容添加到其中。

# 客户端应用程序设置以接收通知

为了让您的应用程序在浏览器中接收通知，它将需要从用户那里获得权限。为此，我们将添加一段代码，显示一个同意对话框，让用户授予您的应用程序在浏览器中接收通知的权限。

我们将在主目录下的`index.jsx`文件中添加`componentWillMount()`方法，因为我们希望在用户成功登录到应用程序后显示对话框：

```jsx
 componentWillMount() {
      firebase.messaging().requestPermission()
       .then(function() {
        console.log('Permission granted.');
        // you can write logic to get the registration token
          // _this.getToken();
       })
       .catch(function(err) {
        console.log('Unable to get permission to notify.', err);
      });
  }
```

请注意，您需要使用以下行导入`firebase`对象：

```jsx
import firebase from '../firebase/firebase-config';
```

一旦您添加了上述代码，请重新启动服务器并登录到应用程序。它应该向您的应用程序用户显示以下对话框：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/1bf6efe5-7577-4d8e-83b2-968da0b20687.png)

用户授予权限后，您的浏览器才能接收通知。

现在，让我们编写一个函数来获取注册令牌：

```jsx
 getToken() {
        console.log("get token");
        firebase.messaging().getToken()
            .then(function (currentToken) {
                if (currentToken) {
                    console.log("current token", currentToken)
                   // sendTokenToServer(currentToken);
                   //updateUI(currentToken);
                } else {
                    // Show permission request.
                    console.log('No Instance ID token available. 
                    Request permission to generate one.');
                    // Show permission UI.
                  // updateUIForPushPermissionRequired();
                   // setTokenSentToServer(false);
                }
            })
            .catch(function (err) {
                console.log('An error occurred while retrieving token. 
                ', err);
              // showToken('Error retrieving Instance ID token. ', 
                 err);
               // setTokenSentToServer(false);
            });
   }
```

上述函数将检索当前访问令牌，需要将其发送到服务器以订阅通知。您可以在`sendTokenToServer()`方法中实现将此令牌发送到服务器的逻辑。

注册令牌可能在您的 Web 应用程序删除注册令牌或用户清除浏览器数据时更改。在后一种情况下，将需要调用`getToken()`来检索新令牌。由于注册令牌可能会更改，您还应该监视刷新令牌以获取新令牌。FCM 在生成令牌时触发回调，以便您可以获取新令牌。`onTokenRefresh()`回调在生成新令牌时触发，因此在其上下文中调用`getToken()`方法可以确保您拥有当前的注册令牌。您可以编写一个类似这样的函数：

```jsx
 refreshToken() {
        firebase.messaging().onTokenRefresh(function () {
            firebase.messaging().getToken()
                .then(function (refreshedToken) {
                    console.log('Token refreshed.');
                    // Indicate that the new Instance ID token has not 
                       yet been sent to the
                    // app server.
                    //setTokenSentToServer(false);
                     Send Instance ID token to app server. Implement it 
                     as per your requirement
                    //sendTokenToServer(refreshedToken);
                    // ...
                })
                .catch(function (err) {
                    console.log('Unable to retrieve refreshed token ', 
                    err);
                    //showToken('Unable to retrieve refreshed token ', 
                      err);
                });
        });
    }
```

一旦您获得令牌，您可以通过实现类似`sendTokenToServer(refreshedToken)`的方法将其发送到您的应用服务器以存储它，如果您正在使用 React 和 Firebase 实时数据库，您可以直接将其存储在数据库中。

所有这些函数将被添加到`index.jsx`文件中。我们将从`componentWillMount()`方法中调用`getToken()`函数，而`refreshToken()`将从构造函数中调用。

现在，在完成所有这些设置之后，我们将在客户端应用程序中添加接收消息的实际功能。

根据页面状态，无论是在后台运行还是在前台（具有焦点）运行，还是关闭或隐藏在标签后面，消息的行为都会有所不同。

为了接收消息，页面必须处理`onMessage()`回调，并且要处理`onMessage()`，您的应用程序中必须定义一个 Firebase 消息服务工作者。

我们将在项目的根目录下创建一个名为`firebase-messaging-sw.js`的文件，并在其中编写以下代码：

```jsx
importScripts('https://www.gstatic.com/firebasejs/4.1.1/firebase-app.js');
importScripts('https://www.gstatic.com/firebasejs/4.1.1/firebase-messaging.js');

var config = {
    messagingSenderId: "41428255555"
};
firebase.initializeApp(config);
const messaging = firebase.messaging();

messaging.setBackgroundMessageHandler(function(payload) {
    console.log('[firebase-messaging-sw.js] Received background message ', payload);
    // Customize notification here
    const notificationTitle = 'Background Message Title';
    const notificationOptions = {
        body: 'Background Message body.',
        icon: '/firebase-logo.png'
    };

return self.registration.showNotification(notificationTitle,
    notificationOptions);
});
```

或者，您可以使用`useServiceWorker`指定现有的服务工作者。

请注意，您需要更新消息`senderId`值，您可以从 Firebase 控制台获取您的项目的值。

如果您希望在您的网页处于后台时显示通知消息，您需要设置`setBackgroundMessageHandler`来处理这些消息。您还可以自定义消息，例如设置自定义标题和图标。您可以在上面的代码片段中检查它。在应用程序处于后台时接收到的消息会触发浏览器中的显示通知。

现在您可以在您的网页上处理`OnMessage()`事件。我们将在我们的`index.js`文件中添加一个构造函数，以便在页面加载时注册回调函数：

```jsx
constructor(props) {
        super(props);
        //this.refreshToken();
        firebase.messaging().onMessage(function (payload) {
            console.log("Message received. ", payload);
            // Update the UI to include the received message.
            console.log("msg", payload);
            // appendMessage(payload);
        });
    }
```

现在我们的客户端已准备好接收通知消息。让我们配置后端以发送通知。

# 服务器设置以发送通知

第一步是为您的项目启用 FCM API。您可以转到[`console.developers.google.com/apis/api/fcm.googleapis.com/overview?project=<project-id>`](https://console.developers.google.com/apis/api/fcm.googleapis.com/overview?project=%3Cproject-id%3E)并启用它。

要从受信任的环境发送通知，我们将需要 Oauth2 访问令牌和我们在客户端应用程序中获取的客户端注册令牌。

要获取 Oauth2 访问令牌，我们将需要来自您服务帐户的私钥。一旦生成私钥，请将包含私钥的 JSON 文件保存在某个安全的地方。我们将使用 Google API 客户端库在[`developers.google.com/api-client-library/`](https://developers.google.com/api-client-library/)检索访问令牌，因此请使用以下命令安装`googleapis`的`npm`模块：

```jsx
npm install googleapis --save
```

以下函数需要添加到我们的`main.js`文件中以获取访问令牌：

```jsx
app.get('/getAccessToken', function (req, res) {

  var { google } = require('googleapis');

  var key = require('./firebase/serviceAccountKey.json');
  var jwtClient = new google.auth.JWT(
    key.client_email,
    null,
    key.private_key,
    ['https://www.googleapis.com/auth/firebase.messaging'], // an array 
     of auth scopes
    null
  );
  jwtClient.authorize(function (err, tokens) {
    if (err) {
      console.log(err);
      res.send(JSON.stringify({
        "token": err
      }));
    }
    console.log("tokens", tokens);
    res.send(JSON.stringify({
      "token": tokens.access_token
    }));
  });

});
```

当您访问`http://localhost:3000/getAccessToken` URL 时，它将在浏览器中显示您的访问令牌。

在浏览器中，您将看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/1215aa7b-ea9b-43a1-8680-4368f5efdda8.png)

显然，在实际应用中，出于安全原因，您不会在浏览器中显示此令牌或在浏览器控制台中打印它，并且您将在内部使用它。

此访问令牌将在请求的`Authorization`标头中传递，如下所示：

```jsx
headers: {
  'Authorization': 'Bearer ' + accessToken
}
```

现在您有了访问令牌。此外，如果您还记得，当设置客户端应用程序时，我们谈到了`sendTokenToServer(currentToken)`方法，该方法将令牌发送到服务器。您现在必须已将其存储在数据库或缓存中，现在可以使用。

现在我们准备发送我们的第一条通知消息。要发送消息，我们将使用最新的 HTTP v1“发送”请求。

我们的请求将如下所示：

```jsx
POST https://fcm.googleapis.com/v1/projects/demoproject-7cc0d/messages:send

Content-Type: application/json
Authorization: Bearer ya29.c.ElphBTDpfvg35hKz4nDu9XYn3p1jlTRgw9FD0ubT5h4prOtwC9G9IKslBv8TDaAPohQHY0-O3JmADYfsrk7WWdhZAeOoqWSH4wTsVyijjhE-PWRSL2YI1erT"

{
  "message":{
    "token" : "dWOV8ukFukY:APA91bFIAEkV-9vwAIQNRGt57XX2hl5trWf8YpocOHfkYAkgSZr5wfBsNozYZOEm_N0mbdZmKbvmtVCCWovrng4UYwj-zmpe36ySPcP31HxGGGb3noEkeBFyZRDUpv0TD7HAKxTfDuEx...",
    "notification" : {
      "body" : "This is an FCM notification message!",
      "title" : "FCM Message",
      }
   }
}
```

您将替换所有令牌并使用您的项目 ID 更新 URL，然后您应该能够发送您的第一条消息。

我使用了一个 rest 客户端来发送消息，并且由于我的浏览器在后台运行，它会在系统托盘中显示通知消息。您可以在下一个截图中看到：

！[](Images/4af8d08c-b8c1-4528-9d2c-b842921e4e5a.png)Postman chrome 工具扩展；目的只是显示发送 FCM 通知消息的请求和响应

请求正文如下：

！[](Images/51c64a73-50bf-428d-86c1-fc39315717ad.png)Postman chrome 工具扩展；图片的目的只是显示我们之前发送的请求的正文

以下是关于消息请求的重要注意事项：

URL：`https://fcm.googleapis.com/v1/projects/<projectid>/messages:send`

+   标头：包含两个键值对：

+   `Content-Type`：`application/json`

+   `Authorization`：`Bearer` <访问令牌>

+   请求正文：包含具有以下键值的消息对象：

+   `token`：<注册令牌，用于向客户端应用发送消息>

+   `notification`：它包含您的通知消息的配置

是的，现在我们已经在我们的应用程序中集成了 FCM，以便将通知消息发送到后台运行应用程序的单个设备。但是，您可能希望将通知发送到一组设备，或者可能希望将消息发送到客户端已订阅的主题。基本概念将保持不变，但配置将发生变化。您可以在 firebase 文档中参考这些主题[`firebase.google.com/docs/cloud-messaging`](https://firebase.google.com/docs/cloud-messaging)。

我们将在下一节中看到云函数。

# 云函数

一般来说，任何软件应用都有一些后端逻辑，这些逻辑部署在服务器上，通过互联网访问。在大型企业级应用程序（如银行或金融）的情况下，可能值得管理一个服务器或一组服务器。然而，在小型应用程序或您希望根据某些用户事件执行特定逻辑的应用程序中，例如数据库中的数据更改或来自移动应用程序或 Web 应用程序的 API 请求，管理服务器可能会增加工作量和成本。但是，当您使用 Firebase 平台时，您不需要担心这一点，因为它提供了**云函数**，让您根据特定 Firebase 产品发出的事件运行代码，而无需管理服务器。

# 云函数的关键特性

云函数具有许多功能，包括与其他 Firebase 产品和第三方 API 的轻松集成，以及强大的安全性和隐私。

云函数的关键特性在以下子主题中讨论。

# 与其他 Firebase 产品和第三方 API 的无缝集成

云函数可以与其他 Firebase 产品和第三方 API 无缝集成。

您的自定义函数可以在特定事件上执行，这些事件可以由列出的 Firebase 产品发出：

+   云 Firestore 触发器

+   实时数据库触发器

+   Firebase 身份验证触发器

+   Firebase 分析触发器

+   云存储触发器

+   云 Pub/Sub 触发器

+   HTTP 触发器

您可以使用 Firebase Admin SDK 来实现不同 Firebase 产品的无缝集成。在一些最常见的应用需求中非常有用。假设您想要在实时数据库中的某些内容发生变化时生成数据库索引或审计日志；您可以编写一个基于实时数据库触发器执行的云函数。反过来，您可以根据特定用户行为执行一些数据库操作。同样地，您可以将云函数与 Firebase 云消息传递（FCM）集成，以便在数据库中发生特定事件时通知用户。

云函数的集成不仅限于 Firebase 产品；您还可以通过编写 Webhook 将云函数与一些第三方 API 服务集成。假设您是开发团队的一部分，并且希望在有人提交代码到 Git 时更新 Slack 频道。您可以使用 Git Webhook API，它将触发您的云函数执行逻辑以将消息发送到 Slack 频道。同样，您可以使用第三方 Auth 提供程序 API，例如 LinkedIn，以允许用户登录。

# 无需维护服务器

云函数在无需购买或维护任何服务器的情况下运行您的代码。您可以编写 JavaScript 或 TypeScript 函数，并使用云上的单个命令部署它。您不需要担心服务器的维护或扩展。Firebase 平台将自动为您管理。服务器实例的扩展发生得非常精确，具体取决于工作负载。

# 私密和安全

应用程序的业务逻辑应该对客户端隐藏，并且必须足够安全，以防止对代码的任何操纵或逆向工程。云函数是完全安全的，因此始终保持私密，并始终按照您的意愿执行。

# 函数的生命周期

云函数的生命周期大致可以分为五个阶段，分别是：

1.  编写新函数的代码，并定义函数应在何时执行的条件。函数定义或代码还包含事件提供程序的详细信息，例如实时数据库或 FCM。

1.  使用 Firebase CLI 部署函数，并将其连接到代码中定义的事件提供程序。

1.  当事件提供程序生成与函数中定义的条件匹配的事件时，它将被执行。

1.  Google 会根据工作负载自动扩展实例的数量。

1.  每当您更新函数的代码或删除函数时，Google 都会自动更新或清理实例。

让我们现在使用实时数据库提供程序创建一个简单的云函数并部署它。

# 设置 Firebase SDK 以用于云函数

在继续初始化云函数之前，必须安装 Firebase CLI。如果尚未安装，可以按照下一节中的说明安装 Firebase CLI。

# Firebase CLI

我们已经在[*第五章*]（5697f854-7bc1-4ffb-86a2-8304d0fc73e7.xhtml）*用户配置文件和访问管理*中看到了如何安装它，但这里是命令，仅供参考：

```jsx
npm install -g firebase-tools
```

一旦我们安装了 Firebase CLI，我们将使用以下命令登录到 firebase 控制台：

```jsx
firebase login
```

这个命令将打开一个浏览器 URL，并要求你登录。成功登录后，你可以进行下一步——初始化 Firebase 项目。

# 初始化 Firebase 云项目

让我们创建一个名为 cloud-functions 的空项目目录。我们将从新创建的 cloud-functions 目录中运行以下命令来初始化云函数：

```jsx
firebase init functions
```

这个命令将引导你通过一个包含不同步骤的向导，并将为你的项目创建必要的文件。它会询问你喜欢的语言：Javascript 还是 TypeScript。我们将选择 Typescript 作为示例。它还会问你是否想要关联任何现有的 firebase 项目或者想要创建一个新项目来关联。我们将选择一个现有的项目。它还会问你是否要安装所需的 node 依赖。我们会选择是，这样它就会安装所有必要的 node 包。如果你想自己管理依赖，可以选择否。以下截图显示了向导的外观：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/e455db7d-42ab-45ad-895e-b49c8e8aea67.png)

最终的结构将如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/a16ae49d-f10b-44ef-bc87-e8075278941f.png)

让我们了解一些特定于云函数的文件：

1.  `firebase.json`：它包含了项目的属性。它包含一个名为"source"的属性，指向`functions`文件夹，用于存放云函数代码。如果你想指向其他文件夹，可以在这里更改。它还包括一个名为"predeploy"的属性，基本上包含了构建和运行代码的命令。

1.  `.firebaserc`：它包含了与该目录相关联的项目。它可以帮助你快速切换项目。

1.  `functions/src/index.ts`：这是主要的源文件，所有的云函数代码都将放在这里。默认情况下，这个文件中已经有一个名为`helloworld`的函数。但是，默认情况下它是被注释掉的。

1.  `functions/package.json`：包含了该项目的 NPM 依赖。

如果你是 Windows 用户，你可能需要将`firebase.json`文件中的"predeploy"属性的值从"`npm` --prefix `$RESOURCE_DIR` run build"改为"`npm` --prefix `%RESOURCE_DIR%` run build"，因为有时在尝试部署函数时会出现错误。

设置完成后，我们就可以部署我们的第一个云函数了。对于这个示例，我们将编写一个简单的函数调用 `greetUser`，它接受 `request` 参数中的用户名称，并在响应中显示问候消息：

```jsx
import * as functions from 'firebase-functions';

export const greetUser = functions.https.onRequest((request, response) => {
        const name = request.query.name;
        response.send("Welcome to Firebase Cloud Function, "+name+"!");
});
```

首先，我们需要导入 f*irebase-functions *来使我们的函数工作。还要注意，云函数是通过调用 `functions.https` 来实现的，这基本上意味着我们正在使用 HTTP 触发器。

`greetUser()` 云函数是一个 HTTP 端点。如果您了解 ExpressJS 编程，您一定注意到语法类似于 ExpressJS 端点，当用户点击端点时，它执行一个带有请求和响应对象的函数。实际上，HTTP 函数的事件处理程序监听 `onRequest()` 事件，支持由 Express web 框架管理的路由器和应用程序。响应对象用于向用户发送响应，在我们的情况下是文本消息，用户将在浏览器中看到。

# 部署和执行云函数

我们需要使用以下命令来部署我们的 `helloworld` 云函数：

```jsx
firebase deploy --only functions
```

这个命令将部署我们的函数，您应该在命令提示符中看到以下响应：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/11742558-0610-45d0-9c6e-ea55e5cf23a2.png)

如果部署成功完成，您将看到函数 URL，例如 `https://us-central1-seat-booking.cloudfunctions.net/greetUser`，现在可以用来触发云函数的执行。

函数 URL 包括以下内容：

+   `us-central1`：这是您的函数部署的区域

+   `seat-booking`：这是 Firebase 项目 ID

+   `cloudfunction.net`：这是默认域

+   `greetUser`：这是部署的函数名称

我们需要将名称属性作为请求参数附加以查看在问候消息中看到的名称。

当您从浏览器中点击该 URL 时，您应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/06c84a54-7799-4579-ac0d-8ded26f83360.png)

所以我们成功创建了一个云函数，耶！

大多数开发人员希望在将函数部署到生产或测试环境之前对其进行单元测试。您可以使用以下命令在本地部署和测试您的函数：

```jsx
firebase serve --only functions
```

它将启动一个本地服务器，并显示一个 URL，您可以点击以测试您的函数：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/7f9cb413-d1ac-413e-a1e9-02cf5f0856a9.png)

在这个例子中，我们看到了如何通过 `functions.https` 使用 HTTP 请求触发函数。现在让我们探索所有触发函数。

# 触发函数

Cloud Functions 可以响应其他 Firebase 产品生成的事件而执行。这些事件本质上是 Cloud Functions 的触发器。我们已经在关键特性部分看到了所有触发器的列表。我们将讨论与本书最相关的实时数据库触发器、身份验证触发器、云存储触发器和云 Firestore 触发器。其余三个可以在 Firebase 文档中进行探索：[`firebase.google.com/docs/functions/`](https://firebase.google.com/docs/functions/)。

# 实时数据库触发器

我们可以创建 Cloud Functions，以响应实时数据库更改来执行某些任务。我们可以使用 `functions.database`* 创建一个新的实时数据库事件函数。*为了指定函数何时执行，我们需要使用可用于处理不同数据库事件的事件处理程序之一。我们还需要指定函数将监听事件的数据库路径。

这里列出了 Cloud Functions 支持的事件：

+   `onWrite()`：当实时数据库中的数据被创建、销毁或更改时触发

+   `onCreate()`：当实时数据库中创建新数据时触发

onUpdate()：当实时数据库中的数据更新时触发

onDelete()：当实时数据库中的数据被删除时触发

我们可以看到示例实时数据库函数，它监听数据库中的用户路径，每当任何用户的数据发生变化时，将其名称转换为大写并将其设置为用户数据库的同级。在这里，我们使用了通配符 `{userId}`，它实质上表示任何 `userId`：

```jsx
import * as functions from 'firebase-functions';
import * as admin from 'firebase-admin';

admin.initializeApp(functions.config().firebase);

export const makeUppercase = functions.database.ref('/users/{userId}')
    .onWrite(event => {
        // Grab the current value of what was written to the Realtime 
           Database.
        const original = event.data.val();
        console.log('Uppercasing', original);
        //status is a property
        const uppercase = original.name.toUpperCase();
        // You must return a Promise when performing asynchronous tasks 
           inside a Functions such as
        // writing to the Firebase Realtime Database.
        // Setting an "uppercase" sibling in the Realtime Database 
           returns a Promise.
        return event.data.ref.parent.child('uppercase').set(uppercase);
});
```

在这里，`event.data` 是一个 DeltaSnapshot。它有一个名为 'previous' 的属性，让您可以检查事件发生前保存在数据库中的内容。previous 属性返回一个新的 DeltaSnapshot，其中所有方法都指向先前的值。

# 身份验证触发器

使用身份验证触发器，我们可以在 Firebase 身份验证创建和删除用户时执行函数代码。

要创建一个在创建新用户时执行的 Cloud 函数，我们可以使用以下代码：

```jsx
exports.userCreated = functions.auth.user().onCreate(event => { ... });
```

根据 Firebase 文档，Cloud Functions 的用户创建事件发生在以下情况下：

+   开发人员使用 Firebase Admin SDK 创建帐户

+   用户创建电子邮件帐户和密码

+   用户首次使用联合身份提供者登录

+   用户首次匿名身份验证登录

当用户首次使用自定义令牌登录时，不会触发 Cloud Functions 事件。如果您想要访问新创建用户的属性，可以使用`event.data`对象进行访问。

例如，您可以按以下方式获取用户的电子邮件和姓名：

```jsx
const user = event.data; 

const email = user.email;
const name = user.displayName;
```

除了用户创建，如果您想要在用户删除时触发函数，可以使用`onDelete()`事件处理程序进行操作：

```jsx
exports.deleteUser = functions.auth.user().onDelete(event => {
  // ...
});
```

# Cloud Storage 触发器

使用 Cloud Storage 触发器，您可以对 Cloud Storage 中的文件和文件夹的创建、更新或删除操作执行 Firebase Cloud Function。我们可以使用*functions.storage.*为 Cloud Storage 事件创建一个新的函数。根据需求，您可以创建一个监听默认存储桶上所有更改的函数，或者可以通过指定存储桶名称来限制它：

```jsx
functions.storage.object() - listen for object changes on the default storage bucket.
functions.storage.bucket('test').object() - listen for object changes on a specific bucket called 'test'
```

例如，我们可以编写一个将上传的文件压缩以减小大小的函数：

```jsx
exports.compressFiles = functions.storage.object().onChange(event => {
  // ...
});
```

*change*事件在对象创建、修改或删除时触发。

Cloud Storage 函数公开了以下属性，可用于进一步处理文件：

+   `event.data`：表示存储对象。

+   `event.data.bucket`：文件存储的存储桶。

+   `event.data.name`：存储桶中的文件路径。

+   `event.data.contentType`：文件内容类型。

+   `event.data.resourceState`：两个可能的值：`exists`或`not_exists`。如果文件/文件夹已被删除，则设置为`not_exists`。

+   `event.data.metageneration`：文件元数据生成的次数；对于新对象，初始值为`1`。

Firebase Cloud Function 的最常见用例是进一步处理文件，例如压缩文件或生成图像文件的缩略图。

# HTTP 触发器

我们已经看到了一个名为`greetUser()`的 HTTP 端点的示例，它涵盖了大部分 HTTP 端点的基本部分。只有一个重要的要点需要注意，我们应该始终正确终止我们的函数；否则，它们可能会继续运行，系统将强制终止它。我们可以使用`send()`、`redirect()`或`end()`来结束我们的函数。

考虑以下示例：

```jsx
response.send("Welcome to the Cloud Function");
```

此外，如果您正在使用 Firebase 托管，并希望将您的 HTTP 端点与某个自定义域连接起来，您也可以这样做。

# Cloud Firestore 触发器

使用 Cloud Firestore 触发器，您的云函数可以监听 Cloud Firestore 发出的事件，每当指定路径上的数据发生更改时，您的函数就会监听到。

在高层次上，它的工作方式类似于实时数据库触发器。您可以使用`functions.firestore`对象来监听特定事件。

它支持四个事件：创建、更新、删除和写入，如下所列：

+   `onWrite()`: 当任何文档被创建、更新或删除时触发

+   `onCreate()`: 当创建新文档时触发

+   `onUpdate()`: 当现有文档中的任何值更改时触发

+   `onDelete()`: 当文档被删除时触发

如果您想在特定文档更改时执行函数，可以编写如下函数：

```jsx
exports.updateUser = functions.firestore
  .document('users/{userID}')
  .onWrite(event => {
    // An object with the current document value
    var document = event.data.data();

    // An object with the previous document value (for update or 
       delete)
    var oldDocument = event.data.previous.data();

    // perform desited database operations ...
});
```

现在我们将讨论云函数终止。

# 函数终止

云函数的优势在于您无需自行采购任何服务器，因此您只需要支付云函数运行的时间。这也给了您一个责任，即正确终止您的函数，不要让您的函数陷入无限循环，否则将在您的账单中产生额外费用。

为了正确终止函数并管理其生命周期，您可以遵循以下推荐方法：

1.  通过返回 JavaScript promise 解决异步处理函数

1.  使用`res.redirect()`、`res.send()`或`res.end()`结束 HTTP 函数

1.  使用`return;`语句结束同步函数

# 总结

在本章中，我们讨论了 Firebase 的两个高级功能：Firebase Cloud Messaging 和 Firebase Cloud Functions。使用这两个功能，您可以开发一个高度交互式的无服务器应用程序。

FCM 是一个可靠的消息传递平台，用于下行和上行消息的可靠传递。我们还讨论了不同的消息类型，并看到何时使用其中一种。为了在 FCM 上有实际经验，我们增强了我们的 Helpdesk 应用程序以发送和接收通知。

我们还谈到了 Firebase 云函数，看到它如何帮助实现无服务器应用。我们介绍了如何开发云函数并将其部署到服务器上。我们还探讨了不同类型的触发器，如实时数据库触发器、HTTP 触发器、Cloud Firestore 触发器、Cloud Storage 触发器和 Auth 触发器。

在下一章中，我们将涵盖其他高级和有趣的功能，比如 Firebase 云存储和将 Firebase 应用与 Google Cloud 集成。


# 第八章：Firebase Cloud Storage

在本章中，我们将讨论 Firebase 的 Cloud Storage 以及它与 Google Cloud 平台的集成。我们还将探讨 Firebase 托管，它允许您在生产级环境上托管您的 Web 应用程序和静态内容（CDN）。

Cloud Storage 提供可扩展和安全的对象存储空间，因为今天大多数企业都需要可扩展的文件存储，考虑到他们通过移动应用程序、Web 应用程序或企业网站收集的大量数据。甚至部署在云上的应用程序也需要存储空间，无论是用于它们自己的资产，如图像、JavaScript、CSS、音频、视频文件，还是用户生成的内容，如文档、视频或音频。

Firebase Cloud Storage 的 SDK 使用 Google Cloud Storage 存储上传的文件。Google Cloud 平台需要一个计费账户来使用其产品，尽管他们提供了一些试用。Firebase Cloud Storage 的 SDK 使用 Google App Engine 免费层中的默认存储桶，因此您不需要计费账户。一旦您的应用程序开始增长，您还可以集成其他产品和服务，如托管计算、App Engine 或 Cloud Functions。

以下是本章将涵盖的主题列表：

+   Google Cloud Storage 概述

+   Google Cloud Storage 的关键特性

+   Google Cloud Storage 支持的存储类别

+   Google Cloud Storage 中安全性和访问控制列表（ACL）的概述

+   Firebase 的 Cloud Storage 的关键特性

+   Cloud Storage 的设置

+   将 Firebase Cloud Storage 与 HelpDesk 应用程序集成，以上传和下载文件

+   Google App Engine 概述

+   Firebase 托管概述

+   在 Firebase 托管上部署 HelpDesk 应用程序的前端

在深入讨论 Firebase 的 Cloud Storage 之前，让我们先讨论 Google Cloud Storage 及其特性。

# Google Cloud Storage

Google Cloud 平台提供了一个安全、可扩展、具有成本效益和高性能的基础设施，包括各种服务，用于开发、管理和运行应用程序所需的一切。Google Cloud Storage 是 Google Cloud 平台的一部分，它是满足您所有对象存储需求的一站式解决方案，从存储到实时流媒体到分析到归档，应有尽有。对象存储是一种高度可扩展和具有成本效益的存储服务，可存储任何类型的数据以其原生格式。

对于您不同的存储需求，Google Cloud Storage 提供不同类别的存储，即多区域存储、区域存储、Nearline 存储和 Coldline 存储。

# Google Cloud Storage 的关键特性

Google Cloud Storage 在以下关键领域提供优势：

+   **耐用性：** Google Cloud Storage 旨在提供 99.999999999%的年度耐用性。数据被冗余存储。当您上传数据时，它会在后台进行复制，并使用自动校验和来确保数据完整性。

+   **可用性：** Google Cloud Storage 提供高可用性，并在您需要时随时提供数据。根据 Google Cloud Storage 文档，多区域存储提供 99.95%的月度可用性，区域存储提供 99.9%的月度可用性。Nearline 和 Coldline 存储提供 99%的月度可用性。

+   **可扩展性：** Google Cloud Storage 具有无限可扩展性，因此可以支持从小型到百亿字节规模的系统。

+   **一致性：** Google Cloud Storage 确保读写一致性，这意味着如果写入成功，对于任何 GET 请求，全球范围内始终返回文档的最新副本。这适用于新建或覆盖对象的`DELETE`或`PUT`。

+   **安全性：** Google Cloud Storage 具有高度安全性，并具有谷歌级别的安全性，以保护您最关键的文档、媒体和资产。它还提供不同的访问控制选项，以便您可以控制谁可以访问存储对象以及在什么级别。

+   **易于使用：** Google Cloud Storage 提供简单易用的 API 和实用工具，用于处理对象存储。

我们需要了解一些 Google Cloud Storage 的基本概念，以便有效地使用它。所以，让我们在这里看看它们：

# 关键概念

Cloud Storage 中的所有数据都属于一个项目。一个项目包括 API、一组用户以及安全和监控设置。您可以创建任意多个项目。在项目内，我们有称为存储桶的数据容器，它们保存我们上传的数据作为对象。对象只是一个文件，还可以选择性地包含描述该文件的一些元数据。

# 存储桶

存储桶是容纳数据的容器。它们就像计算机文件系统中的目录，是您放置数据的基本容器。唯一的区别是，与目录不同，您不能嵌套存储桶。您在云存储中放置的所有内容都必须在存储桶内。存储桶允许您组织数据，并且还允许您控制对数据的访问权限。在设计应用程序时，由于一些强加的存储桶创建和删除速率限制，您应该计划更少的存储桶和大多数情况下更多的对象。每个项目大约每 2 秒可以进行 1 次操作。

创建存储桶时，您需要指定三件事：一个全局唯一的名称，一个默认存储类，以及存储桶及其内容存储的地理位置。如果您在存储对象时没有明确指定对象类别，则您选择的默认存储类将适用于该存储桶内的对象。

一旦创建了存储桶，除非删除并重新创建，否则无法更改存储桶的名称和位置。但是，您可以将其默认存储类更改为存储桶位置中提供的任何其他类。

存储桶名称应该是全局唯一的，并且可以与 CNAME 重定向一起使用。

您的存储桶名称必须满足以下要求：

+   它只能包含小写字母，数字和特殊字符：破折号（-），下划线（_）和点（.）。包含点的名称需要验证。

+   它必须以数字或字母开头和结尾。

+   它必须是 3 到 63 个字符长。包含点的名称可以长达 222 个字符，但是每个以点分隔的组件的长度不能超过 63 个字符。

+   它不能表示 IP 地址，例如`192.168.1.1`。

+   它不能以“goog”前缀开头，也不能包含 google 或 google 的拼写错误。

除了名称，您还可以将称为存储桶标签的键值元数据对与您的存储桶关联起来。存储桶标签允许您将存储桶与其他 Google Cloud Platform 服务（例如虚拟机实例和持久磁盘）分组。每个存储桶最多可以有 64 个存储桶标签。

# 对象

对象是您存储在云存储中的基本实体。您可以在一个存储桶中存储无限数量的对象，因此基本上没有限制。

对象由*对象数据*和对象元数据组成。对象数据通常是一个文件，并且对于云存储来说是不透明的（一块数据）。对象元数据是一组描述对象的键值对。

一个对象名称在存储桶中应该是唯一的；然而，不同的存储桶可以有相同名称的对象。对象名称是 Cloud Storage 中的对象元数据。对象名称可以包含任何组合的 Unicode 字符（UTF-8 编码），并且长度必须小于 1024 字节。

您的对象名称必须满足以下要求：

+   对象名称不得包含回车或换行字符。

+   对象名称不得以 well-known/acme-challenge 开头

您可以在对象名称中包含常见字符斜杠(/)，如果您希望使其看起来好像它们存储在分层结构中，例如/team。

对象名称中常见的字符包括斜杠(/)。通过使用斜杠，您可以使对象看起来好像它们存储在分层结构中。例如，您可以将一个对象命名为`/team/alpha/report1.jpg`，另一个命名为`object/team/alpha/report2.jpg`。当您列出这些对象时，它们看起来好像是基于团队的分层目录结构；然而，对于 Cloud Storage 来说，对象是独立的数据片段，而不是分层结构。

除了名称之外，每个对象都有一个关联的数字，称为**生成编号**。每当您的对象被覆盖时，它的生成编号就会改变。Cloud Storage 还支持一个名为对象版本控制的功能，允许您引用被覆盖或删除的对象。一旦您为一个存储桶启用了对象版本控制，它就会创建一个存档版本的对象，该对象被覆盖或删除，并关联一个唯一的生成编号来唯一标识一个对象。

# 资源

Google Cloud Platform 中的任何实体都是一个资源。无论是项目、存储桶还是对象，在 Google Cloud Platform 中，它都是一个资源。

每个资源都有一个关联的唯一名称来标识它。每个存储桶都有一个资源名称，格式为`projects/_/buckets/`[BUCKET_NAME]，其中[BUCKET_NAME]是存储桶的 ID。每个对象都有一个资源名称，格式为`projects/_/buckets/`[BUCKET_NAME]`/objects/`[OBJECT_NAME]，其中[OBJECT_NAME]是对象的 ID。

还可以在资源名称的末尾附加一个`#[NUMBER]`，表示对象的特定生成版本；`#0`是一个特殊标识符，表示对象的最新版本。当对象的名称以本应被解释为生成编号的字符串结尾时，`#0`会很有用。

# 对象的不可变性

在云存储中，当一个对象被上传后，在其生命周期内无法更改。成功上传对象和成功删除对象之间的时间就是对象的生命周期。这基本上意味着你无法通过追加一些数据或截断一些数据来修改现有对象。但是，你可以覆盖云存储中的对象。请注意，旧版本的文档将在成功上传新版本的文档之前对用户可用。

单个特定对象每秒只能更新或覆盖一次。

现在我们已经了解了云存储的基础知识，让我们来探索云存储中可用的存储类。

# 存储类

Google 云存储支持一系列基于不同用例的存储类。这些包括多区域和区域存储用于频繁访问的数据，近线存储用于较少访问的数据，如您每月不超过一次使用的数据，以及冷线存储用于极少访问的数据，如您每年只使用一次的数据。

让我们逐一了解它们。

# 多区域存储

多区域存储是地理冗余存储；它将您的数据存储在全球各地的多个地理位置或数据中心。它至少在存储桶的多区域位置内以至少 100 英里的距离分隔的两个地理位置存储您的数据。它非常适合低延迟高可用性应用程序，其中您的应用程序为全球用户提供内容，如视频、音频或游戏内容的实时流。由于数据冗余，它提供了高可用性。与其他存储类相比，它的成本略高。

它确保 99.95%的可用性 SLA。由于您的数据保存在多个地方，即使在自然灾害或其他干扰的情况下，它也提供高可用性。

作为多区域存储的数据只能放置在多区域位置，如美国、欧盟或亚洲，而不能放置在特定的区域位置，如 us-central1 或 asia-east1。

# 区域存储

区域存储将数据存储在特定的区域位置，而不是在不同地理位置分布的冗余数据。与多区域存储相比，它更便宜，并确保 99.9%的可用性 SLA。

区域存储更适合存储与使用数据的服务器实例位于同一区域位置的数据。它可以提供更好的性能，并且可以减少网络费用。

# 近线存储

有可能在某个时间点，应用程序或企业只频繁使用所有收集的数据中的一部分。在这种情况下，多区域或区域存储将不是理想的选择，也将是一种昂贵的选择。云存储提供了另一种存储类别，称为近线存储，可以解决之前的问题。这是一种用于存储访问频率较低的数据的低成本存储服务。在需要稍低可用性的情况下，近线存储是比多区域存储或区域存储更好的选择。例如，您每月对整个月份收集的数据进行一次分析。它确保**99.0%的可用性 SLA**。

近线存储也更适合数据备份、灾难恢复和归档存储。然而，需要注意的是，对于一年内访问频率较低的数据，Coldline 存储是最具成本效益的选择，因为它提供了最低的存储成本。

# Coldline 存储

Coldline 存储是一种用于数据归档和灾难恢复的成本非常低、高度耐用的存储服务。虽然它类似于“冷存储”，但它可以低延迟访问您的数据。这是您需要一年一两次的数据的最佳选择。您还可以将每日备份和归档文件存储到 Coldline 中，因为您不需要它们，并且只在灾难恢复时需要它们。它确保**99.0%的可用性 SLA**。

# 标准存储

当用户在创建存储桶时没有指定默认存储类时，它将被视为标准存储对象。在这样的存储桶中创建的没有存储类的对象也被列为标准存储。如果存储桶位于多区域位置，则标准存储等同于多区域存储，当存储桶位于区域存储时，它被视为区域存储。

需要注意的是，定价也会相应发生变化。如果等同于多区域存储，将适用多区域存储的费用。

现在我们了解了不同的存储类别，让我们来了解一下云存储中对象的生命周期管理。

# 生命周期管理

许多应用程序需要在一定时间后删除或归档旧资源的功能。以下是一些示例用例：

1.  将超过 1 年的文件从多区域存储移动到 Coldline 存储。

1.  从 Coldline 存储中删除超过 5 年的文件。

1.  如果启用了对象版本控制，只保留少量最近的对象版本。

幸运的是，Google Cloud Storage 提供了一个名为对象生命周期管理的功能，根据配置自动处理这种类型的操作。配置是一组适用于启用了此功能的存储桶的规则。

例如，以下规则指定删除超过 365 天的文件：

```jsx
// lifecycle.json
{
  "lifecycle": {
    "rule":
    [
      {
        "action": {"type": "Delete"},
        "condition": {"age": 365}  
      }
    ]
  }
}
```

# API 和工具

Google Cloud Platform 为云存储提供 SDK，还为不同平台的其他产品提供了一些 SDK，如 Node.js、Java、Python、Ruby、PHP 和 go。如果您不使用任何客户端库，它还提供 REST API。它还提供一个名为**gsutil**的命令行工具，允许您执行对象管理任务，包括以下内容：

+   上传、下载和删除对象

+   列出存储桶和对象

+   移动、复制和重命名对象

+   编辑对象和存储桶的 ACL

# 访问控制

有许多选项可用于管理存储桶和对象的访问权限。让我们看一下总结：

1.  **身份和访问管理**（**IAM**）权限：为您的项目和存储桶提供广泛的控制。它对于授予对存储桶的访问权限并允许对存储桶内的对象进行批量操作非常有用。

1.  **访问控制列表**（**ACL**）：为用户授予对单个存储桶或对象的读取或写入访问权限提供了细粒度的控制。

1.  签名 URL（查询字符串认证）：通过签名 URL 在有限的时间内为对象授予读取或写入访问权限。

1.  **签名策略文档**：允许您定义规则并对可以上传到存储桶的对象执行验证，例如，基于文件大小或内容类型进行限制。

1.  **Firebase 安全规则**：提供了细粒度和基于属性的规则语言，以使用 Firebase SDK 为云存储提供移动应用和 Web 应用的访问权限。

现在我们熟悉了 Google Cloud Storage 的关键概念，让我们回到 Firebase 的云存储。

# Firebase 云存储的关键特性

Firebase 云存储继承了 Google 云存储的优势或特性。然而，它还具有一些额外的特性，比如声明性安全规则语言，用于指定安全规则。

云存储的关键特点如下：

1.  **易用性和健壮性：**Firebase 云存储是一种简单而强大的解决方案，用于存储和检索用户生成的内容，如文档、照片、音频或视频。它提供了强大的上传和下载功能，使得文件传输在互联网连接中断时暂停，并在重新连接时从中断处恢复。这既节省时间又节省了互联网带宽。云存储的 API 也很简单，可以通过 Firebase SDK 来使用。

1.  **强大的安全性：**当涉及到云存储时，我们首先想到的是安全性。它足够安全吗？我的文件会发生什么？这些问题显而易见，也很重要。答案是肯定的，Firebase 云存储非常安全。它拥有 Google 安全性的力量。它与 Firebase 身份验证集成，为开发人员提供直观的身份验证。您还可以使用声明性安全规则来限制对文件的访问，根据内容类型、名称或其他属性。

1.  **高可扩展性：**Firebase 云存储由 Google 基础设施支持，提供了一个高度可扩展的存储环境，使您可以轻松地将应用程序从原型扩展到生产环境。这个基础设施已经支持了最流行和高流量的应用程序，如 Youtube、Google 照片和 Spotify。

1.  **成本效益：**云存储是一种成本效益的解决方案，您只需为所使用的内容付费。您无需购买和维护用于托管文件的服务器。

1.  **与其他 Firebase 产品良好集成：**云存储与其他 Firebase 产品良好集成，例如，在我们的上一章中，我们已经看到云存储触发器可以触发云函数，根据云存储上的文件操作执行一些逻辑。

我们已经了解了 Firebase 云存储的关键特点和优势。让我们看看它是如何实际运作的。

# 它是如何工作的？

Firebase SDK 用于云存储可以直接从客户端上传和下载文件。客户端能够重试或恢复操作，节省用户的时间和带宽。

在幕后，Cloud Storage 将您的文件存储在 Google Cloud Storage 存储桶中，因此可以通过 Firebase 和 Google Cloud 两者访问。这使您可以通过 Firebase SDK 从移动客户端上传和下载文件，并使用 Google Cloud 平台进行服务器端处理，例如生成图像缩略图或视频转码。由于 Cloud Storage 可以自动扩展，因此可以处理各种类型的应用程序数据，从小型到中型到大型应用程序。

在安全方面，Firebase Cloud Storage 的 SDK 与 Firebase 身份验证无缝集成，以识别用户。正如我们在第六章中所看到的，*Firebase 安全性和规则*，Firebase 还提供了声明性规则语言，让您控制对单个文件或文件组的访问。

让我们增强我们的 Helpdesk 应用程序，用户可以上传其个人资料图片。

# 设置 Cloud Storage

使用 Firebase SDK，我们可以轻松地在我们的应用程序中集成和设置 Firebase 的 Cloud Storage。

要设置 Cloud Storage，您将需要存储桶的 URL，您可以从我们的 Firebase 控制台获取。您可以从`Storage`菜单的`Files`选项卡中获取，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/c614fd16-cc49-4962-81d6-0fc10c6b72b8.png)

一旦获得了引用，就可以将其添加到 Firebase 配置中。

考虑这个例子：

```jsx

import firebase from 'firebase';

const config = {
    apiKey: "AIzaSyDO1VEnd5VmWd2OWQ9NQkkkkh-ehNXcoPTy-w",
    authDomain: "demoproject-7cc0d.firebaseapp.com",
    databaseURL: "https://demoproject-7cc0d.firebaseio.com",
    projectId: "demoproject-7cc0d",
    storageBucket: "gs://demoproject-7cc0d.appspot.com",
    messagingSenderId: "41428255555"
};

export const firebaseApp = firebase.initializeApp(config);

// Get a reference to the storage service,
var storage = firebase.storage();
```

现在我们准备使用 Cloud Storage。现在我们需要创建一个引用，用于在文件层次结构中导航。

我们可以通过调用`ref()`方法来获取引用，就像这样：

```jsx
var storage = firebase.storage();
```

您还可以创建对树中特定下级节点的引用。例如，要获取对`images/homepage.png`的引用，我们可以这样写：

```jsx
var homepageRef = storageRef.child('images/homepage.jpg');
```

您还可以在文件层次结构中导航到上层或下层：

```jsx
// move to the parent of a reference - refers to images  var imagesRef = homepageRef.parent;

//move to highest parent or top of the bucket
var rootRef = homepageRef.root;

//chaining can be done for root, parent and child for multiple times
homepageRef.parent.child('test.jpg'); 
```

三个属性——**fullPath**、**name**和**bucket**——可用于引用以更好地理解引用的文件：

```jsx
// File path is 'images/homepage.jpg'
var path = homepageRef.fullPath

// File name is 'homepage.jpg'
var name = homepageRef.name

// Points to 'images'
var imagesRef = homepageRef.parent;
```

现在我们准备好进行上传功能。我们将扩展我们的 HelpDesk 应用程序，并为用户提供上传截图以及票务的其他细节的功能。我们将把上传的图片存储在 Cloud Storage for Firebase 中，并仅从那里检索。

# 上传文件

您可以上传文件或 Blob 类型、Uint8Array 或 base64 编码的字符串来上传文件到 Cloud Storage。对于我们的示例，我们将使用文件类型。如前所述，首先我们需要获取文件的完整路径的引用，包括文件名。

我们将修改`AddTicketForm.jsx`文件，以允许用户上传与票务相关的截图或图像。

现在，`src/add-ticket/'AddTicketForm.jsx'`文件看起来像下面这样。更改部分已用粗体标出并附有注释：

```jsx
import React, { Component } from 'react';
import firebase from '../firebase/firebase-config';
import { ToastSuccess, ToastDanger } from 'react-toastr-basic';

class AddTicketForm extends Component {

  constructor(props) {
    super(props);
    this.handleSubmitEvent = this.handleSubmitEvent.bind(this);
    this.handleChange = this.handleChange.bind(this);
    this.onChange = this.onChange.bind(this);
    console.log(props.userInfo);

    this.state = {
      uId: props.userId,
      email: props.userInfo[0].email,
      issueType: "",
      department: "",
      comment: "",
      snapshot: null
    }
  }

  handleChange(event) {
    console.log(event.target.value);
    this.setState({
      [event.target.id]: event.target.value
    });
  }

  //handle onchange - set the snapshot value to the file selected
  onChange(e) {
 console.log("ff ",e.target.files[0] );
 this.setState({snapshot:e.target.files[0]})
 }

  handleSubmitEvent(e) {
    e.preventDefault();
    var storageRef = firebase.storage().ref();

 // Create a reference to 'image'
 var snapshotRef = storageRef.child('ticket_snapshots/'+this.state.snapshot.name);

 //get a reference to 'this' in a variable since in callback this will point to different object
 var _this = this;
 snapshotRef.put(this.state.snapshot).then(function(res) {
 console.log('Uploaded a blob or file!');
 console.log(res.metadata);

 const userId = _this.state.uId;
 var data = {
 date: Date(),
 email: _this.state.email,
 issueType: _this.state.issueType,
 department: _this.state.department,
 comments: _this.state.comment,
 status: "progress",
 snapshotURL: res.metadata.downloadURLs[0]  //save url in db to use it for download
 }

 console.log(data);

 var newTicketKey = firebase.database().ref('/helpdesk').child('tickets').push().key;
 // Write the new ticket data simultaneously in the tickets list and the user's ticket list.
 var updates = {};
 updates['/helpdesk/tickets/' + userId + '/' + newTicketKey] = data;
 updates['/helpdesk/tickets/all/' + newTicketKey] = data;

 return firebase.database().ref().update(updates).then(() => {
 ToastSuccess("Saved Successfully!!");
 this.setState({
 issueType: "",
 department: "",
 comment: "",
 snapshot: _this.state.snapshot
 });
 }).catch((error) => {
 ToastDanger(error.message);
 });

 });

    //React form data object

  }
 //render() method - snippet given below
}
export default AddTicketForm;
```

让我们理解上述代码：

1.  在状态中添加一个 snapshot 属性。

1.  `OnChange()` - 注册`onChange()`事件，将文件设置在状态中的快照字段中。

1.  `onHandleSubmit()` - 我们已经创建了一个文件的引用，将其存储在名为`'ticket_snapshots'`的文件夹中，存储在 Firebase Cloud 存储中。一旦文件成功上传，我们将从响应元数据中获取一个下载 URL，并将其与其他票务详情一起存储在我们的实时数据库中。

您还需要在`render()`方法中进行一些 HTML 更改，以添加用于文件选择的输入字段：

```jsx
 render() {
    var style = { color: "#ffaaaa" };
    return (
      <form onSubmit={this.handleSubmitEvent} >
        <div className="form-group">
          <label htmlFor="email">Email <span style={style}>*</span></label>
          <input type="text" id="email" className="form-control"
            placeholder="Enter email" value={this.state.email} disabled  
            required onChange={this.handleChange} />
        </div>
        <div className="form-group">
          <label htmlFor="issueType">Issue Type <span style={style}> *</span></label>
          <select className="form-control" value={this.state.issueType} 
          id="issueType" required onChange={this.handleChange}>
            <option value="">Select</option>
            <option value="Access Related Issue">Access Related 
            Issue</option>
            <option value="Email Related Issues">Email Related 
             Issues</option>
            <option value="Hardware Request">Hardware Request</option>
            <option value="Health & Safety">Health & Safety</option>
            <option value="Network">Network</option>
            <option value="Intranet">Intranet</option>
            <option value="Other">Other</option>
          </select>
        </div>
        <div className="form-group">
          <label htmlFor="department">Assign Department
        <span style={style}> *</span></label>
          <select className="form-control" value={this.state.department} id="department" required onChange={this.handleChange}>
            <option value="">Select</option>
            <option value="Admin">Admin</option>
            <option value="HR">HR</option>
            <option value="IT">IT</option>
            <option value="Development">Development</option>
          </select>
        </div>
        <div className="form-group">
          <label htmlFor="comments">Comments <span style={style}> *</span></label>
          (<span id="maxlength"> 200 </span> characters left)
            <textarea className="form-control" rows="3" id="comment" value={this.state.comment} onChange={this.handleChange} required></textarea>
        </div>
        <div className="form-group">
 <label htmlFor="fileUpload">Snapshot</label>
 <input id="snapshot" type="file" onChange={this.onChange} />
 </div>
        <div className="btn-group">
          <button type="submit" className="btn btn-
          primary">Submit</button>
          <button type="reset" className="btn btn-
          default">cancel</button>
        </div>
      </form>
    );
  }
```

我们的 add-ticket 表单看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/9ba63b07-30eb-4922-a971-0c9cd9981db7.png)

然后，您可以检查您的 Firebase 控制台，看看文件上传是否正常工作。以下屏幕截图显示，我们上传的文件（`helpdesk-db.png`）已成功保存在 Firebase 的 Cloud Storage 中：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/e5bc6f40-a481-4337-9395-563dd1a977bd.png)

如前所述，Firebase 的 Cloud 存储与 Google Cloud 存储高度集成，并使用 Google Cloud 存储的存储桶来存储文件。您可以登录到 Google Cloud 平台的控制台[`console.cloud.google.com/storage`](https://console.cloud.google.com/storage)并在存储部分进行检查。您还应该在那里看到您上传的所有文件。

下一个屏幕截图显示，文件可以从 Google Cloud 平台控制台中查看：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/bd9d81f6-eae8-40fb-aba8-e85c0049e973.png)

现在，您还可以检查您的数据库，看看已创建的票务是否具有快照 URL 属性和相应的值-文件的 downloadURL。

数据库的以下屏幕截图显示，快照 URL 已正确存储：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/56f4ed56-165e-4da7-8b64-6c5324fc9125.png)

耶！云存储已与我们的应用集成。但是，我们还没有完成。我们需要允许用户查看已上传的图像，因此我们还将实现下载文件功能。但是，在我们转到下载文件功能之前，我想提到您应更新云存储的安全规则以控制对文件的访问。根据默认规则，要执行所有文件的`.read`和`.write`操作，需要 Firebase 身份验证。

默认规则如下图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/6fbfacaa-6461-4a1d-9bbd-885484366869.png)

但是，您应根据自己的需求进行更新。

# 添加文件元数据

当您上传文件时，还可以为该文件存储一些元数据，例如 Content-Type 或名称。

您可以创建一个带有键值对的 JSON 对象，并在上传文件时传递该对象。对于自定义元数据，您可以在元数据对象内创建一个对象，如下所示：

```jsx
// Create file metadata including the content type  var metadata =  { contentType:  'image/jpeg',
 customMetadata: {
      'ticketNo':'12345'
  } };  // Upload the file and metadata  var uploadTask = storageRef.child('folder/file.jpg').put(file, metadata);
```

# 管理上传和错误处理

云存储允许您管理文件上传；您可以恢复、暂停或取消上传。相应的方法可在`UploadTask`上使用，该方法由`put()`或`putString()`返回，可用作承诺或用于管理和监视上传的状态：

```jsx
// Upload the file and metadata  var uploadTask = storageRef.child('folder/file.jpg').put(file);  // Pause the upload - state changes to pause uploadTask.pause();  // Resume the upload - state changes to running uploadTask.resume();  // Cancel the upload - returns an error indicating file upload is cancelled uploadTask.cancel();
```

您可以使用'state_change'观察者来监听进度事件。如果您想要为文件上传显示实时进度条，这非常有用：

| **事件类型** | **用途** |
| --- | --- |
| 运行中 | 当任务开始或恢复上传时，会触发此事件。 |
| 进度 | 当任何数据上传到云存储时，会触发此事件。用于显示上传进度条。 |
| 暂停 | 当上传暂停时，会触发此事件。 |

当事件发生时，将传回一个**TaskSnapshot**对象，可用于查看事件发生时的任务。

对象被传回。它包含以下属性：

| 属性 | 类型 | 描述 |
| --- | --- | --- |
| 传输的字节数 | `数字` | 在拍摄快照时已传输的总字节数。 |
| 总字节数 | `数字` | 要上传的总字节数。 |
| 状态 | `firebase.storage.TaskState` | 当前上传状态 |
| 元数据 | `firebaseStorage.Metadata` | 包含服务器在上传完成时发送的元数据；在那之前，包含发送到服务器的元数据。 |
| 任务 | `firebaseStorage.UploadTask` | 可用于暂停、取消或恢复任务。 |
| ref | `firebaseStorage.Reference` | 该任务来源的引用。 |

当您上传文件时，可能会发生一些错误。您可以使用回调中获得的错误对象来处理错误。

以下代码片段显示了管理文件上传和错误处理的示例代码：

```jsx
// File
var file = this.state.snapshot;

// Create the file metadata
var metadata = {
  contentType: 'image/jpeg'
};

// Upload file and metadata to the object 'images/mountains.jpg'
var uploadTask = storageRef.child('ticket_snapshots/' + file.name).put(file, metadata);

// Listen for state changes, errors, and completion of the upload.
uploadTask.on(firebase.storage.TaskEvent.STATE_CHANGED, // or 'state_changed'
  function(snapshot) {
    // Get task progress, including the number of bytes uploaded and the total number of bytes to be uploaded
    var progress = (snapshot.bytesTransferred / snapshot.totalBytes) * 100;
    console.log('Upload is ' + progress + '% done');
    switch (snapshot.state) {
      case firebase.storage.TaskState.PAUSED: // or 'paused'
        console.log('Upload is paused');
        break;
      case firebase.storage.TaskState.RUNNING: // or 'running'
        console.log('Upload is running');
        break;
    }
  }, function(error) {

  // A full list of error codes is available at
  // https://firebase.google.com/docs/storage/web/handle-errors
  switch (error.code) {
    case 'storage/unauthorized':
      // User doesn't have permission to access the object
      break;

    case 'storage/canceled':
      // User canceled the upload
      break;

    case 'storage/unknown':
      // Unknown error occurred, inspect error.serverResponse
      break;
  }
}, function() {
  // Upload completed successfully, now we can get the download URL
  var downloadURL = uploadTask.snapshot.downloadURL;
});
```

现在，让我们转到下载文件部分。

# 下载文件

要下载文件，您需要使用文件的`https://或 gs://` URL 获取对该文件的引用，或者您可以通过将子路径附加到存储根来构造它。

下一个代码片段显示了这些方法：

```jsx
var storage = firebase.storage();  var pathReference = storage.ref('images/stars.jpg');  // Create a reference from a Google Cloud Storage URI  var gsReference = storage.refFromURL('gs://bucket/folder/file.jpg')  // Create a reference from an HTTPS URL  // Note that in the URL, characters are URL escaped!  var httpsReference = storage.refFromURL('https://firebasestorage..../file.jpg')
```

我们将扩展我们的 HelpDesk 应用程序，以允许用户查看已上传的票据的快照。您需要更新`ticket-listing`文件夹下的`ViewTickets.jsx`文件中的代码。我们已经从数据库中获取了一个 URL，因此我们不需要获取下载 URL 的引用：

```jsx
 componentDidMount() {
    const itemsRef = firebase.database().ref('/helpdesk/tickets/'+this.props.userId);

    itemsRef.on('value', (snapshot) => {
      let tickets = snapshot.val();
      if(tickets != null){
        let ticketKeys = Object.keys(tickets);
        let newState = [];
        for (let ticket in tickets) {
          newState.push({
            id:ticketKeys,
            email:tickets[ticket].email,
            issueType:tickets[ticket].issueType,
            department:tickets[ticket].department,
            comments:tickets[ticket].comments,
            status:tickets[ticket].status,
            date:tickets[ticket].date,
            snapshotURL: tickets[ticket].snapshotURL
        });
      }
        this.setState({
          tickets: newState
        });
      }
    });
}

render() {
    return (
        <table className="table">
        <thead>
        <tr> 
            <th>Email</th>
            <th>Issue Type</th> 
            <th>Department</th> 
            <th>Comments</th>
            <th>Status</th> 
            <th>Date</th> 
            <th>Snapshot</th> 
        </tr>
        </thead>
        <tbody>
              {

                this.state.tickets.length > 0 ?
                this.state.tickets.map((item,index) => {
                return (

                  <tr key={item.id[index]}>
                    <td>{item.email}</td>
                    <td>{item.issueType}</td> 
                    <td>{item.department}</td> 
                    <td>{item.comments}</td>
                    <td>{item.status === 'progress'?'In Progress':''}</td> 
                    <td>{item.date}</td> 
                    <th><a target="_blank" href={item.snapshotURL}>View</a></th> 
                  </tr>
                )
              }) :
              <tr>
                <td colSpan="5" className="text-center">No tickets found.</td>
              </tr>
            }
        </tbody>
        </table>
    );
```

就像上传文件一样，您也需要以类似的方式处理下载的错误。

现在，让我们看看如何从云存储中删除文件。

# 删除文件

要删除文件，您首先需要获取对文件的引用，就像我们在上传和下载中看到的那样。一旦您获得了引用，就可以调用`delete()`方法来删除文件。它返回一个承诺，如果成功则解决，如果出现错误则拒绝。

考虑这个例子：

```jsx
// Create a reference to the file to delete  var fileRef = storageRef.child('folder/file.jpg');  // Delete the file desertRef.delete().then(function()  {  // File deleted successfully  }).catch(function(error)  {  // an error occurred!  });
```

现在，让我们看看什么是 Google App Engine。

# Google App Engine

Google App Engine 是一个“平台即服务”，它抽象了基础设施的担忧，让您只关注代码。它提供了一个根据接收的流量量自动扩展的平台。您只需要上传您的代码，它就会自动管理您的应用程序的可用性。Google App Engine 是向 Firebase 应用程序添加额外处理能力或受信任执行的简单快速的方法。

如果您有一个 App Engine 应用程序，您可以使用内置的 App Engine API 在 Firebase 和 App Engine 之间共享数据，因为 Firebase 云存储的 SDK 使用 Google App Engine 默认存储桶。这对于执行计算密集型的后台处理或图像操作非常有用，例如创建上传图像的缩略图。

Google App Engine 标准环境提供了一个环境，您的应用在其中以受支持的语言的运行时环境运行，即 Python 2.7、Java 8、Java 7、PHP 5.5 和 Go 1.8、1.6。如果您的应用代码需要这些语言的其他版本或需要其他语言，您可以使用 Google App Engine 灵活环境，在该环境中，您的应用在运行在 Google Cloud 虚拟机上的 docker 容器上。

这两个环境之间有许多不同之处，可以在 Google Cloud 文档中进行探索[`cloud.google.com/appengine/docs/the-appengine-environments`](https://cloud.google.com/appengine/docs/the-appengine-environments)。

如果您想将现有的 Google Cloud Platform 项目导入 Firebase，并希望使任何现有的 App Engine 对象可用，您需要通过运行以下命令使用`gsutil`设置对象的默认访问控制，以允许 Firebase 访问它们。

```jsx
gsutil -m acl ch -r -u firebase-storage@system.gserviceaccount.com:O gs://<your-cloud-storage-bucket>
```

# Firebase 托管

Firebase Hosting 提供了一种安全且简单的方式来在 CDN 上托管您的静态网站和资源。Hosting 的主要特点如下：

1.  通过安全连接提供：内容始终通过 SSL 安全地传输

1.  更快的内容传递：文件在全球的 CDN 边缘被缓存，因此内容传递更快。

1.  更快的部署：您可以在几秒钟内使用 Firebase CLI 部署您的应用

1.  轻松快速的回滚：如果出现任何错误，只需一个命令即可回滚

Hosting 提供了部署和管理静态网站所需的所有基础设施、功能和工具，无论是单页面应用还是复杂的渐进式应用。

默认情况下，您的网站将托管在[firebaseapp.com](http://firebaseapp.com)域的子域上。使用 Firebase CLI，您可以将计算机上的本地目录中的文件部署到您的托管服务器上。

当您将您的网站移至生产环境时，您可以将您自己的域名连接到 Firebase Hosting。

# 部署您的网站

您需要安装 Firebase CLI 来部署您的静态网页应用。

Firebase CLI 可以通过一个命令进行安装：

```jsx
npm install -g firebase-tools
```

现在，让我们在云上部署我们的 HelpDesk 应用程序。我们有两个 HelpDesk 项目：react 应用（一个名为 code 的项目）和服务器应用（一个名为 node 的项目）。让我们首先在 Firebase Hosting 上托管或部署我们的客户端 react 应用。

进入您的项目目录（代码）并运行以下命令来初始化配置：

```jsx
firebase init
```

如下截图所示，它会问您“您想为此文件夹设置哪个 Firebase 功能？”，您需要选择“Hosting”：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/5e9c4046-1632-42c6-8ed2-bb6a9d80a672.png)

它将在项目的根目录中创建一个 `firebase.json` 文件。`firebase.json` 的结构将如下所示：

```jsx
{
  "database": {
    "rules": "database.rules.json"
  },
  "hosting": {
    "public": "build",
    "ignore": [
      "firebase.json",
      "**/.*",
      "**/node_modules/**"
    ],
    "rewrites": [
      {
        "source": "**",
        "destination": "/index.html"
      }
    ]
  }
}
```

public 属性告诉 Firebase 要上传到托管的目录。该目录必须存在于您的项目目录中。

您现在可以使用以下命令部署您的站点：

```jsx
firebase deploy
```

它会要求您进行 Firebase CLI 登录。您可以使用以下命令来执行：

```jsx
firebase login --reauth
```

成功登录后，您可以再次运行 `firebase deploy` 命令来部署您的应用程序：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/1a036823-cfec-46b2-99da-c2f952d67116.png)

成功部署后，您将获得项目的 Hosting URL，类似于 `https://YOUR-FIREBASE-APP>.firebaseapp.com`。在我们的案例中，它是 *[`demoproject-7cc0d.firebaseapp.com/`](https://demoproject-7cc0d.firebaseapp.com/)。*现在您可以转到生成的 URL 并确认它是可访问的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/ae4a3a72-2561-4adb-a3a2-78b4f3d0d585.png)

耶！我们已经在 Firebase Hosting 上部署了我们的第一个应用程序。您还可以在 Firebase 控制台的 Hosting 部分检查 URL：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/1f6101cd-a142-4dcd-b7af-62700798d521.png)

您还可以通过单击**连接域**按钮来配置您的自定义域。它将引导您通过向导来配置您自己的域名。

# 摘要

本章介绍了 Google 云平台。它为您提供了对 Google 云存储和 Google 应用引擎的基本理解，以及我们如何将 Firebase 的云存储与 Google 云存储集成。我们探索了 Firebase 的云存储，并看到了如何将文件上传、下载和删除到云存储。我们还扩展了 HelpDesk 应用程序，允许用户上传屏幕截图以及工单详细信息，并查看/下载已上传的图像。此外，我们还探讨了如何在 Firebase Hosting 上部署我们的应用程序。

在下一章中，我们将讨论开发人员在使用 React 和 Firebase 时应遵循的编码标准和最佳实践，以获得更好的应用程序性能、减少错误数量，以及更易于管理的应用程序代码。


# 第九章：最佳实践

在深入探讨在处理 React 和 Firebase 时应遵循的最佳实践之前，让我们回顾一下之前章节中我们所看到的内容。

在之前的章节中，我们看到了 Firebase 账户设置，Firebase 与 ReactJs 的集成，使用 Firebase 身份验证提供程序进行登录认证，React 组件中的身份验证状态管理，基于角色和配置文件的数据安全，Firebase 与 React-Redux 的集成，Firebase 云消息传递，Firebase 云函数，以及在 React 组件中使用 Firebase Admin SDK API，希望你也享受了这段旅程。现在我们知道从哪里开始以及如何编写代码，但最重要的是如何遵循最佳实践编写标准的代码。

因此，当我们使用 React 和 Firebase 创建应用程序时，我们需要确保 Firebase 数据库中数据的结构以及将数据传递到 React 组件中是应用程序中最重要的部分。

在开发领域中，每个开发人员对于遵循最佳实践都有自己的看法，但我将与您分享我迄今为止观察和经验到的内容；你可能有不同的看法。

以下是本章将涵盖的主题列表：

+   Firebase 的最佳实践

+   React 和 Redux 的最佳实践

# Firebase 的最佳实践

在 Firebase 中，我们都知道数据以 JSON 树格式存储，并且实时同步到每个连接的设备。因此，在使用 Firebase 构建跨平台应用程序（Web、iOS 和 Android）时，我们可以共享一个实例给所有应用程序，以接收来自实时数据库的最新更新和新数据。因此，当我们将数据添加到 JSON 树中时，它将成为现有 JSON 结构中的一个节点，并带有关联的键，因此我们始终需要计划如何保存数据以构建一个结构良好的数据库。

# 写入数据

在 Firebase 中，我们有四种方法可以将数据写入 Firebase 数据库：

| `set( )` | 写入或替换数据到指定路径，比如 `messages/tickets/<uid>`。 |
| --- | --- |
| `update( )` | 更新节点的特定子节点而不替换其他子节点。我们还可以使用 update 方法将数据更新到多个位置。 |
| `push( )` | 要在数据库中添加一系列数据，我们可以使用`push()`方法；每次调用时它都会生成一个唯一的 ID，比如 `helpdesk/tickets/<unique-user-id>/<unique-ticket-id>`。 |
| `transaction( )` | 当我们处理可能会被并发更新破坏的复杂数据时，我们可以使用这种方法，比如增量计数器。 |

现在，让我们看看我们的帮助台应用程序中的数据结构是如何构建的：

```jsx
{
 "tickets": {
 "-L4L1BLYiU-UQdE6lKA_": {
    "comments": "Need extra 4GB RAM in my system"
    "date": "Fri Feb 02 2018 15:51:10 GMT+0530 (India Standa..."
    "department": "IT"
    "email": "harmeet_15_1991@yahoo.com"
    "issueType": "Hardware Request"
    "status": "progress"
 },
 "-L4K01hUSDzPXTIXY9oU": {
 "comments": "Need extra 4GB RAM in my system"
 "date": "Fri Feb 02 2018 15:51:10 GMT+0530 (India Standa..."
 "department": "IT"
 "email": "harmeet_15_1991@yahoo.com"
 "issueType": "Hardware Request"
 "status": "progress"
     }
  }
}
```

现在，让我们以前面的数据结构为例，使用`set()`方法存储具有自增整数的数据：

```jsx
{
 "tickets": {
 "0": {
    "comments": "Need extra 4GB RAM in my system"
    "date": "Fri Feb 02 2018 15:51:10 GMT+0530 (India Standa..."
    "department": "IT"
    "email": "harmeet_15_1991@yahoo.com"
    "issueType": "Hardware Request"
    "status": "progress"
 },
 "1": {
 "comments": "Need extra 4GB RAM in my system"
 "date": "Fri Feb 02 2018 15:51:10 GMT+0530 (India Standa..."
 "department": "IT"
 "email": "harmeet_15_1991@yahoo.com"
 "issueType": "Hardware Request"
 "status": "progress"
     }
  }
}
```

现在，如果你看到前面的数据结构，新的票将被存储为`/tickets/1`。如果只有一个用户添加票，这将起作用，但在我们的应用程序中，许多用户可以同时添加票。如果两个员工同时写入`/tickets/2`，那么其中一个票将被另一个删除。因此，这不是推荐的做法，我们始终建议在处理数据列表时使用`push()`方法生成唯一 ID（参考前面的数据结构）。

# 避免嵌套数据

在 Firebase 实时数据库中，当我们从 JSON 树中获取数据时，我们还将获取该特定节点的所有子节点，因为当我们将数据添加到 JSON 树中时，它就成为现有 JSON 结构中的一个节点，并带有关联的键。 Firebase 实时数据库允许嵌套数据深达 32 级，因此当我们授予某人在特定节点上的读取或写入权限时，我们也在给予该节点下所有子节点的访问权限。因此，始终最佳实践是尽可能保持我们的数据结构扁平化。

让我向你展示为什么嵌套数据是不好的；请参考以下示例：

```jsx
{
 // a poorly nested data architecture, because
 // iterating over "products" to get a list of names requires
 // potentially downloading hundreds of products of mobile
 "products": {
 "electronics": {
 "name": "mobile",
 "types": {
 "samsung": { "name": "Samsung S7 Edge (Black Pearl, 128 GB)", "description": "foo" },
 "apple": { ... },
 // a very long list of mobile products
 }
 }
 }
 }
```

使用这种嵌套数据结构，对数据进行迭代非常困难。即使是像列出产品名称这样的简单操作，也需要将整个产品树，包括所有产品列表和类型，下载到客户端。

# Flattern 数据结构

在 Flattern 结构中，数据被分成不同的路径；只需在需要时轻松下载所需的节点：

```jsx
{
      // products contains only meta info about each product
      // stored under the product's unique ID
      "products": {
        "electronics": {
          "name": "mobile"
        },
        "home_furniture": { ... },
        "sports": { ... }
      },
      // product types are easily accessible (or restricted)
      // we also store these by product Id
      "types": {
          "mobile":{
              "name":"samsung"
           },
      "laptop": {...},
      "computers":{...},
      "television":{...}
      "home_furniture": { ... },
      "sports": { ... }
      },
      // details are separate from data we may want to iterate quickly
      // but still easily paginated and queried, and organized by 
         product ID
      "detail": {
        "electronics": {
          "samsung": { "name": "Samsung S7 Edge (Black Pearl, 128 GB)", 
          "description": "foo" },
          "apple": { ... },
          "mi": { ... }
        },
        "home_furniture": { ... },
        "sports": { ... }
      }
    }
```

在前面的例子中，我们有一些轻度嵌套的数据（例如，每个产品的详细信息本身就是带有子元素的对象），但我们还按照它们将来的迭代和读取方式逻辑地组织了我们的数据。我们存储了重复的数据来定义对象之间的关系；这对于维护双向、多对多或一对多的冗余关系是必要的。这使我们能够快速有效地获取手机，即使产品或产品类型的列表扩展到数百万，或者 Firebase 规则和安全性将阻止访问某些记录。

现在可以通过每个产品只下载少量字节来迭代产品列表，快速获取用于在 UI 中显示产品的元数据。

在看到前面的扁平结构后，如果您认为在 Firebase 中逐个查找每条记录是可以的，那么是的，因为 Firebase 内部使用网络套接字和客户端库进行传入和传出请求的优化。即使我们有数万条记录，这种方法仍然可以，并且非常合理。

始终创建可以在应用用户增长时扩展的数据结构。

# 避免使用数组

Firebase 文档已经提到并澄清了这个话题，避免在 Firebase 数据库中使用数组，但我想强调一些使用数组存储数据的用例。

请参考以下几点；如果以下所有条件都成立，我们可以使用数组在 Firebase 中存储数据：

+   如果一个客户端一次只能写入数据

+   在删除键时，我们可以保存数组并进行切割，而不是使用`.remove()`

+   当通过数组索引引用任何内容时，我们需要小心（可变键）

# 日期对象

当我们谈论在 Firebase 中对数据进行排序和过滤时，确保您在每个创建的对象中都添加了`created_date`键，以及日期时间戳，例如`ref.set(new Date().toString())`和`ref.set(new Date().getTime())`，因为 Firebase 不支持 JavaScript 日期对象类型（`ref.set(new Date());`）。

# 自定义声明

Firebase Admin SDK 提供了在配置文件对象中添加自定义属性的功能；借助这一功能，我们可以为用户提供不同的访问控制，包括在 react-firebase 应用中基于角色的控制，因此它们并不是用来存储额外的数据（如配置文件和其他自定义数据）。我们知道这看起来是一个非常方便的方法，但强烈不建议这样做，因为这些声明存储在 ID 令牌中，这会影响性能问题，因为所有经过身份验证的请求都包含与已登录用户对应的 Firebase ID 令牌。

+   自定义声明仅用于存储控制用户访问的数据

+   自定义声明的大小受限，因此传递大于 1000 字节的自定义声明将引发错误

# 管理用户会话

管理用户会话并提示重新验证，因为每次用户登录时，用户凭据都会发送到 Firebase 身份验证后端并交换为 Firebase ID 令牌（JWT）和刷新令牌。

以下是我们需要管理用户会话的常见情况：

+   用户被删除

+   用户被禁用

+   电子邮件地址和密码更改

Firebase Admin SDK 还提供了使用`revokeRefreshToken()`方法撤销特定用户会话的能力。它会撤销给定用户的活动刷新令牌。如果重置密码，Firebase 身份验证后端会自动撤销用户令牌。

当任何数据需要身份验证才能访问时，必须配置以下规则：

```jsx
{
 "rules": {
 "users": {
 "$user_id": {
 ".read": "$user_id === auth.uid && auth.token.auth_time > (root.child('metadata').child(auth.uid).child('revokeTime').val() || 0)",
 ".write": "$user_id === auth.uid && auth.token.auth_time > (root.child('metadata').child(auth.uid).child('revokeTime').val() || 0)"
 }
 }
 }
}
```

# 在 JavaScript 中启用离线功能

当我们使用 Firebase 创建实时应用程序时，还需要监视客户端与数据库的连接和断开连接。Firebase 提供了一个简单的解决方案，可以在客户端从 Firebase 数据库服务器断开连接时写入数据库。我们可以在断开连接时执行所有操作，如写入、设置、更新和删除。

参考 Firebase 的`onDisconnect()`方法示例：

```jsx
var presenceRef = firebase.database().ref("disconnectmessage");
// Write the string when client loses connection
presenceRef.onDisconnect().set("I disconnected!");
```

我们还可以附加回调函数以确保`onDisconnect()`方法被正确附加：

```jsx
presenceRef.onDisconnect().remove(function(err) {
 if (err) {
 console.error('onDisconnect event not attached properly', err);
 }
});
```

要取消`onDisconnect()`方法，我们可以调用`.cancel()`方法`onDisconnectRef.cancel();`。

为了检测连接状态，Firebase 实时数据库提供了特殊位置`/.info/connected`。

每次应用连接状态更改时都会更新；它返回布尔值以检查客户端连接状态是否已连接：

```jsx
var connectedRef = firebase.database().ref(".info/connected");
connectedRef.on("value", function(snap) {
 if (snap.val() === true) {
 alert("connected");
 } else {
 alert("not connected");
 }
});
```

# 优化数据库性能

还有一些需要关注的事项，比如在您的应用中优化 Firebase 实时数据库性能，以了解如何使用不同的实时数据库监控工具来优化您的实时数据库性能。

# 监控实时数据库

我们可以通过一些不同的工具收集我们的实时数据库性能数据：

+   **高级概述：** 我们可以使用 Firebase 分析工具列出未索引的查询和实时读/写操作的概述。要使用分析工具，请确保已安装 Firebase CLI 并运行以下命令。

+   **计费使用估计：** Firebase 使用指标在 Firebase 控制台中提供您的计费使用和高级性能指标。

+   **详细钻取：** Stackdriver 监控工具为您提供了数据库随时间性能的更细粒度查看。

有关分析的更多详细信息，请访问[`firebase.google.com/docs/database/usage/profile`](https://firebase.google.com/docs/database/usage/profile)

# 通过指标改善性能

收集数据后，根据您想要改进的性能领域，探索以下最佳实践和策略：

| **指标** | **描述** | **最佳实践** |
| --- | --- | --- |

| 负载/利用率 | 优化数据库处理请求时的容量利用率（反映在**负载**或**io/database_load**指标中）。 | 优化数据结构（[`firebase.google.com/docs/database/usage/optimize#data-structure`](https://firebase.google.com/docs/database/usage/optimize#data-structure)）跨数据库共享数据（[`firebase.google.com/docs/database/usage/optimize#shard-data`](https://firebase.google.com/docs/database/usage/optimize#shard-data)）

提高监听器效率（[`firebase.google.com/docs/database/usage/optimize#efficient-listeners`](https://firebase.google.com/docs/database/usage/optimize#efficient-listeners)）

使用基于查询的规则限制下载*(*[`firebase.google.com/docs/database/usage/optimize#query-rules`](https://firebase.google.com/docs/database/usage/optimize#query-rules))

优化连接（[`firebase.google.com/docs/database/usage/optimize#open-connections`](https://firebase.google.com/docs/database/usage/optimize#open-connections)）|

| 活动连接 | 平衡数据库的同时和活动连接数，以保持在 100,000 个连接限制以下。 | 在数据库之间分片数据 ([`firebase.google.com/docs/database/usage/optimize#shard-data`](https://firebase.google.com/docs/database/usage/optimize#shard-data)) 减少新连接 ([`firebase.google.com/docs/database/usage/optimize#open-connections`](https://firebase.google.com/docs/database/usage/optimize#open-connections)) |
| --- | --- | --- |

| 出站带宽 | 如果从数据库下载的数据量比您想要的要高，您可以提高读操作的效率并减少加密开销。 | 优化连接 ([`firebase.google.com/docs/database/usage/optimize#open-connections`](https://firebase.google.com/docs/database/usage/optimize#open-connections)) 优化数据结构 ([`firebase.google.com/docs/database/usage/optimize#data-structure`](https://firebase.google.com/docs/database/usage/optimize#data-structure)) |

使用基于查询的规则限制下载 ([`firebase.google.com/docs/database/usage/optimize#query-rules`](https://firebase.google.com/docs/database/usage/optimize#query-rules))

重用 SSL 会话 ([`firebase.google.com/docs/database/usage/optimize#ssl-sessions`](https://firebase.google.com/docs/database/usage/optimize#ssl-sessions))

提高监听器效率 ([`firebase.google.com/docs/database/usage/optimize#efficient-listeners`](https://firebase.google.com/docs/database/usage/optimize#efficient-listeners))

限制对数据的访问 ([`firebase.google.com/docs/database/usage/optimize#secure-data`](https://firebase.google.com/docs/database/usage/optimize#secure-data)) |

| 存储 | 确保您不存储未使用的数据，或者在其他数据库和/或 Firebase 产品之间平衡存储的数据，以保持在配额范围内。 | 清理未使用的数据 ([`firebase.google.com/docs/database/usage/optimize#cleanup-storage`](https://firebase.google.com/docs/database/usage/optimize#cleanup-storage)) 优化数据结构 ([`firebase.google.com/docs/database/usage/optimize#data-structure`](https://firebase.google.com/docs/database/usage/optimize#data-structure))

在数据库之间分片数据 ([`firebase.google.com/docs/database/usage/optimize#shard-data`](https://firebase.google.com/docs/database/usage/optimize#shard-data))

使用 Firebase 存储([`firebase.google.com/docs/storage`](https://firebase.google.com/docs/storage)) |

来源：[`firebase.google.com/docs/database/usage/optimize`](https://firebase.google.com/docs/database/usage/optimize)

如果我们使用的是 Blaze 定价计划，我们可以创建多个实时数据库实例；然后，我们可以在同一个 Firebase 项目中创建多个数据库实例。

要从 Firebase CLI 编辑和部署规则，请按照以下步骤进行：

```jsx
firebase target:apply database main my-db-1 my-db-2
firebase target:apply database other my-other-db-3
Update firebase.json with the deploy targets:
{
"database": [
{"target": "main", "rules", "foo.rules.json"},
{"target": "other", "rules": "bar.rules.json"}
]
}
```

```jsx
firebase deploy 
```

确保您始终从同一位置编辑和部署规则。

# 将您的应用连接到多个数据库实例

使用数据库引用来访问存储在辅助数据库实例中的数据。您可以通过 URL 或应用程序获取特定数据库实例的引用。如果我们在`.database()`方法中不指定 URL，那么我们将获得应用程序的默认数据库实例的引用：

```jsx
// Get the default database instance for an app
var database = firebase.database();
// Get a secondary database instance by URL
var database = firebase.database('https://reactfirebaseapp-9897.firebaseio.com');
```

要查看 Firebase 示例项目列表，请访问[`firebase.google.com/docs/samples/`](https://firebase.google.com/docs/samples/)。

查看 Firebase 库列表，请参考[`firebase.google.com/docs/libraries/`](https://firebase.google.com/docs/libraries/)。

您也可以订阅[`www.youtube.com/channel/UCP4bf6IHJJQehibu6ai__cg`](https://www.youtube.com/channel/UCP4bf6IHJJQehibu6ai__cg)频道以获取更新。

# React 和 Redux 的最佳实践

每当我们有具有动态功能的组件时，数据就会出现；同样，在 React 中，我们必须处理动态数据，这似乎很容易，但并非每次都是这样。

听起来很混乱！

这很容易，但有时很困难，因为在 React 组件中，很容易通过多种方式传递属性来构建渲染树，但更新视图的清晰度不高。

在前面的章节中，这个声明已经清楚地显示出来了，所以如果你还不清楚，请参考那些。

# Redux 的使用

我们知道，在单页面应用程序（SPA）中，当我们必须处理状态和时间时，难以掌握状态随时间的变化。在这里，Redux 非常有帮助，为什么？这是因为在 JavaScript 应用程序中，Redux 处理两种状态：一种是数据状态，另一种是 UI 状态，它是单页面应用程序（SPA）的标准选项。此外，请记住，Redux 可以与 Angular 或 Jquery 或 React JavaScript 库或框架一起使用。

# Redux 和 Flux 之间的区别

Redux 是一个工具，而 Flux 只是一个模式，你不能像即插即用或下载一样使用它。我并不否认 Redux 受到 Flux 模式的一些影响，但正如我们无法说它百分之百看起来像 Flux 一样。

让我们继续参考一些区别。

Redux 遵循三个指导原则，如所示，这也将涵盖 Redux 和 Flux 之间的区别：

1.  **单一存储器方法：** 我们在之前的图表中看到，存储器在应用程序和 Redux 中充当所有状态修改的“中间人”。它通过存储器控制两个组件之间的直接通信，是通信的单一点。在这里，Redux 和 Flux 之间的区别在于 Flux 有多个存储器方法，而 Redux 有单一存储器方法。

1.  **只读状态：** 在 React 应用程序中，组件不能直接改变状态，而是必须通过“动作”将改变分派给存储器。在这里，存储器是一个对象，它有四种方法，如下所示：

+   store.dispatch(action)

+   store.subscribe(listener)

+   store.getState()

+   replaceReducer(nextReducer)

1.  **改变状态的 Reducer 函数：** Reducer 函数将处理分派动作以改变状态，因为 Redux 工具不允许两个组件直接通信；因此它不仅会改变状态，还会描述状态改变的分派动作。这里的 Reducer 可以被视为纯函数。以下是编写 reducer 函数的一些特点：

+   没有外部数据库或网络调用

+   基于参数返回值

+   参数是“不可变的”

+   相同的参数返回相同的值

Reducer 函数被称为纯函数，因为它们纯粹地根据其设置的参数返回值；它没有任何其他后果。建议它们具有扁平状态。在 Flux 或 Redux 架构中，处理来自 API 返回的嵌套资源总是很困难，因此建议在组件中使用扁平状态，例如 normalize。

**专业提示：** `const data = normalize(response, arrayOf(schema.user))  state = _.merge(state, data.entities)`

# 不可变的 React 状态

在扁平状态中，我们可以处理嵌套资源，并且在不可变对象中，我们可以获得声明的状态不可修改的好处。

不可变对象的另一个好处是，通过它们的引用级别相等检查，我们可以获得出色的改进渲染性能。在不可变中，我们有一个`shouldComponentUpdate`的例子：

```jsx
shouldComponentUpdate(nexProps) { 
 // instead of object deep comparsion
 return this.props.immutableFoo !== nexProps.immutableFoo
}
```

在 JavaScript 中，使用不可变性深冻结节点将帮助您在变异之前冻结节点，然后它将验证结果。以下示例显示了相同的逻辑：

```jsx
return { 
  ...state,
  foo
}
return arr1.concat(arr2) 
```

我希望前面的例子已经清楚地说明了不可变 JS 的用途和好处。它也有一个不复杂的方式，但它的使用率非常低：

```jsx
import { fromJS } from 'immutable'
const state = fromJS({ bar: 'biz' }) 
const newState = foo.set('bar', 'baz') 
```

在我看来，这是一个非常快速和美丽的功能。

# React 路由

我们必须在客户端应用程序中使用路由，并且对于 ReactJS，我们还需要一个或另一个路由库，因此我建议您使用 react-router-dom 而不是 react-router。

**优势：**

+   在标准化结构中声明视图可以帮助我们立即了解我们的应用视图是什么

+   使用 react-router-dom，我们可以轻松处理嵌套视图及其渐进式视图分辨率

+   使用浏览历史功能，用户可以向后/向前导航并恢复视图状态

+   动态路由匹配

+   导航时视图上的 CSS 过渡

+   标准化的应用程序结构和行为，在团队合作时非常有用。

注意：React 路由器没有提供处理数据获取的任何方式。我们需要使用 async-props 或其他 React 数据获取机制。

很少有开发人员知道如何在 webpack 中将应用程序代码拆分成多个 JavaScript 文件：

```jsx
require.ensure([], () => { 
  const Profile = require('./Profile.js')
  this.setState({
    currentComponent: Profile
  })
})
```

代码的拆分是必要的，因为每个代码对每个用户都没有用，也没有必要在每个页面加载该代码块，这对浏览器来说是一种负担，因此为了避免这种情况，我们应该将应用程序拆分成几个块。

现在，你可能会有一个问题，比如如果我们有更多的代码块，我们将不得不有更多的 HTTP 请求，这也会影响性能，但借助 HTTP/2 多路复用，你的问题将得到解决。您还可以将分块代码与分块哈希结合使用，这样每当更改代码时，还可以优化浏览器缓存比例。

# JSX 组件

JSX 无非就是，简单来说，它只是 JavaScript 语法的扩展。此外，如果您观察 JSX 的语法或结构，您会发现它类似于 XML 编码。JSX 正在执行预处理步骤，将 XML 语法添加到 JavaScript 中。虽然您当然可以在没有 JSX 的情况下使用 React，但 JSX 使得 React 更加整洁和优雅。与 XML 类似，JSX 标记具有标记名称，属性和子级，并且在其中，如果属性值用引号括起来，该值将成为字符串。

JSX 的工作方式类似于 XML，具有平衡的开放和关闭标签，并且有助于使大型树更容易阅读，而不是“函数调用”或“对象文字”。

**在 React 中使用 JSX 的优势**：

+   JSX 比 JavaScript 函数更容易理解和思考

+   JSX 的标记更熟悉于设计师和您团队的其他成员

+   您的标记变得更语义化，结构化和更有意义

它有多容易可视化？

正如我所说，结构/语法在 JSX 格式中更容易可视化/注意到，这意味着与 JavaScript 相比更清晰和可读。

# 语义/结构化语法

在我们的应用程序中，我们可以看到 JSX 语法易于理解和可视化；在其背后，有一个具有语义化语法结构的重要原因。JSX 愉快地将您的 JavaScript 代码转换为更具语义和有意义的结构化标记。这使您能够声明组件结构和信息倾注使用类似 HTML 的语法，知道它将转换为简单的 JavaScript 函数。React 概述了您在 React.DOM 命名空间中期望的所有 HTML 元素。好处是它还允许您在标记中使用您自己编写的自定义组件。

# 在 React 组件中使用 PropType

在 React 组件中，我们可以从更高级别的组件传递属性，因此对属性的了解是必须的，因为这将使您能够更灵活地扩展组件并节省时间：

```jsx
MyComponent.propTypes = { 
  isLoading: PropTypes.bool.isRequired,
  items: ImmutablePropTypes.listOf(
    ImmutablePropTypes.contains({
      name: PropTypes.string.isRequired,
    })
  ).isRequired
}
```

您还可以验证您的属性，就像我们可以使用 react 不可变 proptypes 验证不可变 JS 的属性一样。

# 高阶组件的好处

高阶组件只是原始组件的扩展版本：

```jsx
PassData({ foo: 'bar' })(MyComponent) 
```

使用它的主要好处是我们可以在多种情况下使用它，例如身份验证或登录验证：

```jsx
requireAuth({ role: 'admin' })(MyComponent) 
```

另一个好处是，使用高阶组件，您可以单独获取数据并设置逻辑以简单地查看您的视图。

# Redux 架构的好处

与其他框架相比，它有更多的优点：

1.  它可能没有任何其他影响。

1.  正如我们所知，不需要绑定，因为组件不能直接交互。

1.  状态是全局管理的，因此管理不当的可能性较小。

1.  有时，对于中间件，管理其他方式的影响可能会很困难。

从上述观点来看，Redux 架构非常强大，而且具有可重用性。

我们还可以使用 ReactFire 库构建 React-Firebase 应用程序，只需几行 JavaScript。我们可以通过 ReactFireMixin 将 Firebase 数据集成到 React 应用程序中。

# 总结

在本书的最后一章中，我们介绍了在使用 React 和 Firebase 时应遵循的最佳实践。我们还看到了如何使用不同的工具来监视应用程序性能，以减少错误的数量。我们还谈到了 Firebase 实时数据库中数据结构的重要性，并讨论了动态数据传递给 React 组件。我们还研究了其他关键因素，如 JSX、React 路由和 React PropTypes，在 React 应用程序中是最常用的元素。我们还了解到 Redux 在维护**单页应用程序**（**SPAs**）的状态方面有很大帮助。
