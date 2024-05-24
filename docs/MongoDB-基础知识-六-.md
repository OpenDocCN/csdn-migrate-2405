# MongoDB 基础知识（六）

> 原文：[`zh.annas-archive.org/md5/804E58DCB5DC268F1AD8C416CF504A25`](https://zh.annas-archive.org/md5/804E58DCB5DC268F1AD8C416CF504A25)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：MongoDB 中的备份和恢复

概述

在本章中，我们将详细研究如何将备份、样本和测试数据库加载到目标 MongoDB 实例中，同样重要的是，你将学会如何导出现有数据集以备份和恢复。到本章结束时，你将能够将 MongoDB 数据备份、导出、导入和恢复到现有服务器中。这使你能够从灾难中恢复数据，以及快速将已知信息加载到系统进行测试。

# 介绍

在之前的章节中，我们主要依赖预加载到 MongoDB Atlas 实例中的样本数据。除非你在进行新项目，否则这通常是数据库首次出现的方式。然而，当你被雇佣或转移到一个包含 MongoDB 数据库的不同项目时，它将包含在你开始之前创建的所有数据。

现在，如果你需要一个本地副本来测试你的应用程序或查询呢？直接对生产数据库运行查询通常是不安全或不可行的，因此将数据集复制到测试环境是非常常见的过程。同样，当创建一个新项目时，你可能希望将一些样本数据或测试数据加载到数据库中。在本章中，我们将研究迁移、导入或导出现有 MongoDB 服务器的程序，并设置一个包含现有数据的新数据库的程序。

注意

在本章中，包括的练习和活动都是对一个场景的迭代。数据和示例都基于名为`sample_mflix`的 MongoDB Atlas 示例数据库。

在本章期间，我们将按照一个理论场景进行一系列练习。这是对*第七章*“数据聚合”和*第八章*“在 MongoDB 中编写 JavaScript”中涵盖的场景的扩展。你可能还记得，一个电影院连锁要求你创建查询和程序，分析他们的数据库，以制作在促销季期间放映的电影列表。

在这些章节中，你已经构建了一些聚合，其输出是包含摘要数据的新集合。你还创建了一个应用程序，使用户可以以编程方式更新电影。公司对你的工作非常满意，他们决定将整个系统迁移到更重要、更好的硬件上。尽管系统管理员们对将现有的 MongoDB 实例迁移到新硬件上感到自信，但你决定最好手动测试该过程，以确保在需要时能够提供帮助。

# MongoDB 实用程序

mongo shell 不包括导出、导入、备份或恢复的功能。然而，MongoDB 已经创建了方法来实现这一点，因此不需要脚本工作或复杂的图形用户界面。为此，提供了几个实用程序脚本，可以用于批量将数据进出数据库。这些实用程序脚本包括：

+   `mongoimport`

+   `mongoexport`

+   `mongodump`

+   `mongorestore`

我们将在接下来的章节中详细介绍这些实用程序。正如它们的名称所示，这四个实用程序对应于导入文档、导出文档、备份数据库和恢复数据库。我们将从导出数据的主题开始。

# 导出 MongoDB 数据

在批量移动数据进出 MongoDB 时，最常见且通用的实用程序是`mongoexport`。这个命令很有用，因为它是从 MongoDB 中提取大量数据的主要方式之一。将 MongoDB 数据导出到 JSON 文件中，可以让你将其与其他应用程序或数据库一起使用，并与 MongoDB 之外的利益相关者共享数据。

重要的是要注意，`mongoexport` 必须在指定的单个数据库和集合上运行。 不能在整个数据库或多个集合上运行 `mongoexport`。 我们将在本章后面看到如何完成类似这样的更大范围的备份。 以下片段是 `mongoexport` 的示例：

```js
mongoexport --uri=mongodb+srv://USERNAME:PASSWORD@provendocs-fawxo.gcp.mongodb.net/sample_mflix –quiet --limit=10 --sort="{theaterId:1}" --collection=theaters --out=output.json
```

这个例子是一个更复杂的命令，其中包括一些可选参数并明确设置其他参数。 但是在实践中，您的导出命令可能会简单得多。 这里使用的结构和参数在下一节中有详细解释。

## 使用 mongoexport

学习 `mongoexport` 语法的最佳方法是逐个参数地构建命令。 所以让我们从最简单的导出开始：

```js
mongoexport –-collection=theaters
```

正如您所看到的，命令的最简单形式只需要一个参数：`–-collection`。 此参数是我们希望导出文档的集合。

如果执行此命令，可能会遇到一些令人困惑的结果，如下所示：

```js
2020-03-07-T13:16:09.152+1100 error connecting to db server: no reachable servers
```

我们得到这个结果是因为我们没有指定数据库或 URI。 在这种情况下，`mongoexport` 默认使用本地 MongoDB 的端口 27017 和默认数据库。 由于在上一章的示例和练习中我们一直在 Atlas 上运行我们的 MongoDB 服务器，让我们更新我们的命令以指定这些参数。

注意

您不能同时指定数据库和 URI；这是因为数据库是 URI 的一部分。 在本章中，我们将使用 URI 进行导出。

更新后的命令如下所示：

```js
mongoexport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlasServer.gcp.mongodb.net/sample_mflix --collection=theaters
```

现在您有一个有效的命令，可以针对 MongoDB Atlas 数据库运行它。 您将看到以下输出：

```js
2020-08-17T11:07:23.302+1000    connected to: mongodb+srv://[**REDACTED**]@performancetuning.98afc.gcp.mongodb.net/sample_mflix
{"_id":{"$oid":"59a47286cfa9a3a73e51e72c"},"theaterId":1000,"location":  {"address":{"street1":"340 W Market","city":"Bloomington","state":"MN","zipcode":"55425"},"geo":  {"type":"Point","coordinates":[-93.24565,44.85466]}}}
{"_id":{"$oid":"59a47286cfa9a3a73e51e72d"},"theaterId":1003,"location":  {"address":{"street1":"45235 Worth Ave.","city":"California","state":"MD","zipcode":"20619"},"geo":  {"type":"Point","coordinates":[-76.512016,38.29697]}}}
{"_id":{"$oid":"59a47286cfa9a3a73e51e72e"},"theaterId":1008,"location":  {"address":{"street1":"1621 E Monte Vista Ave","city":"Vacaville","state":"CA","zipcode":"95688"},"geo":  {"type":"Point","coordinates":[-121.96328,38.367649]}}}
{"_id":{"$oid":"59a47286cfa9a3a73e51e72f"},"theaterId":1004,"location":  {"address":{"street1":"5072 Pinnacle Sq","city":"Birmingham","state":"AL","zipcode":"35235"},"geo":  {"type":"Point","coordinates":[-86.642662,33.605438]}}}
```

在输出的末尾，您应该看到导出的记录数：

```js
{"_id":{"$oid":"59a47287cfa9a3a73e51ed46"},"theaterId":952,"location":  {"address":{"street1":"4620 Garth Rd","city":"Baytown","state":"TX","zipcode":"77521"},"geo":  {"type":"Point","coordinates":[-94.97554,29.774206]}}}
{"_id":{"$oid":"59a47287cfa9a3a73e51ed47"},"theaterId":953,"location":  {"address":{"street1":"10 McKenna Rd","city":"Arden","state":"NC","zipcode":"28704"},"geo":  {"type":"Point","coordinates":[-82.536293,35.442486]}}}
2020-08-17T11:07:24.992+1000    [########################]  sample_mflix.theaters  1564/1564  (100.0%)
2020-08-17T11:07:24.992+1000    exported 1564 records
```

使用指定的 URI，导出操作成功，并且您可以看到从 `theatres` 集合中的所有文档。 但是，将所有这些文档淹没在输出中并不是很有用。 您可以使用一些 shell 命令将此输出管道或附加到文件中，但是 `mongoexport` 命令在其语法中提供了另一个参数，用于自动输出到文件。 您可以在以下命令中看到此参数 (`--out`)：

```js
mongoexport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlasServer.gcp.mongodb.net/sample_mflix --collection=theaters --out=output.json
```

运行此命令后，您将看到以下输出：

```js
2020-08-17T11:11:44.499+1000    connected to: mongodb+srv://[**REDACTED**]@performancetuning.98afc.gcp.mongodb.net/sample_mflix
2020-08-17T11:11:45.634+1000    [........................]  sample_mflix.theaters  0/1564  (0.0%)
2020-08-17T11:11:45.694+1000    [########################]  sample_mflix.theaters  1564/1564  (100.0%)
2020-08-17T11:11:45.694+1000    exported 1564 records
```

现在，在该目录中创建了一个名为 `output.json` 的新文件。 如果您查看此文件，您可以看到我们从 theatres 集合中导出的文档。

参数 `uri`、`collection` 和 `out` 可以满足大多数导出用例。 一旦您的数据在磁盘上的文件中，就很容易将其与其他应用程序或脚本集成。

## mongoexport 选项

现在我们知道了 `mongoexport` 的三个最重要的选项。 但是，还有一些其他有用的选项可帮助从 MongoDB 导出数据。 以下是其中一些选项及其效果：

+   `--quiet`：此选项减少了在导出期间发送到命令行的输出量。

+   `--type`：这将影响文档在控制台中的打印方式，默认为 JSON。 例如，您可以通过指定 CSV 来以 **逗号分隔值** (**CSV**) 格式导出数据。

+   `--pretty`：这以良好格式的方式输出文档。

+   `--fields`：这指定要导出的文档中的键的逗号分隔列表，类似于导出级别的投影。

+   `--skip`：这类似于查询级别的跳过，跳过导出的文档。

+   `--sort`：这类似于查询级别的排序，按某些键对文档进行排序。

+   `--limit`：这类似于查询级别的限制，限制输出的文档数量。

以下是一个示例，其中使用了一些这些选项，本例中将排序的十个 `theatre` 文档输出到名为 `output.json` 的文件中。 此外，还使用了 `--quiet` 参数：

```js
mongoexport --uri=mongodb+srv://USERNAME:PASSWORD@provendocs-fawxo.gcp.mongodb.net/sample_mflix --quiet --limit=10 --sort="{theaterId:1}" --collection=theaters --out=output.json
```

由于我们使用了 `--quiet` 选项，因此将不会看到任何输出。

```js
> mongoexport --uri=mongodb+srv://testUser:testPassword@performancet uning.98afc.gcp.mongodb.net/sample_mflix --quiet --limit=10 --sort="{theaterId:1}" --collection=theaters --out=output.json
>
```

但是，如果我们查看`output.json`文件的内容，我们可以看到按 ID 排序的十个文档：

![图 11.1：output.json 文件的内容（已截断）](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_11_01.jpg)

图 11.1：output.json 文件的内容（已截断）

还有另一个选项可用于更高级的导出，那就是查询选项。查询选项允许您指定一个查询，使用与标准 MongoDB 查询相同的格式。只有匹配此查询的文档将被导出。将此选项与`--fields`、`--skip`和`--limit`等其他选项结合使用，可以定义一个完整的查询，并将其格式化输出，然后将其导出到文件中。

以下是使用查询选项返回特定文档子集的导出。在这种情况下，我们正在获取所有`theaterId`为`4`的电影院。

```js
mongoexport --uri=mongodb+srv://USERNAME:PASSWORD@provendocs-fawxo.gcp.mongodb.net/sample_mflix --query="{theaterId: 4}" --collection=theaters
```

注意

在 MacOS 上，您可能需要用引号括起`theaterId`，例如：`--query="{\"theaterId\": 4}"`

现在我们将看到我们正在寻找的文档如下：

```js
2020-08-17T11:22:48.559+1000    connected to: mongodb+srv://[**REDACTED**]@performancetuning.98afc.gcp.mongodb.net/sample_mflix
{"_id":{"$oid":"59a47287cfa9a3a73e51eb78"},"theaterId":4,"location":  {"address":{"street1":"13513 Ridgedale Dr","city":"Hopkins","state":"MN","zipcode":"55305"},"geo":  {"type":"Point","coordinates":[-93.449539,44.969658]}}}
2020-08-17T11:22:48.893+1000    exported 1 record
```

让我们在下一个练习中使用这些选项。

## 练习 11.01：导出 MongoDB 数据

在开始本练习之前，让我们重新审视一下*介绍*部分中概述的电影公司的情景。假设您的客户（电影公司）将迁移其现有数据，您担心会丢失宝贵的信息。您决定的第一件事是将数据库中的文档导出为 JSON 文件，以防灾难发生，可以将其存储在廉价的云存储中。此外，您将为每个电影类别创建不同的导出。

注意

为了展示对`mongoexport`的了解，我们将不为每个类别创建一个导出，而只为单个类别创建一个。您还只会导出前三个文档。

在这个练习中，您将使用`mongoexport`创建一个名为`action_movies.json`的文件，其中包含按发行年份排序的三部动作电影。以下步骤将帮助您完成任务：

1.  调整您的导出并保存以备后用。创建一个名为`Exercise11.01.txt`的新文件，以存储您的导出命令。

1.  接下来，只需输入标准的`mongoexport`语法，包括 URI 和`movies`集合：

```js
mongoexport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/sample_mflix --collection=movies
```

1.  添加额外的参数以满足您的条件。首先，将您的导出输出到名为`action_movies.json`的文件中。使用`--out`参数如下：

```js
mongoexport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/sample_mflix --collection=movies --out=action_movies.json
```

1.  接下来，根据本练习的规范，添加您的排序条件以按发行年份对电影进行排序。您可以使用`--sort`来实现：

```js
mongoexport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/sample_mflix --collection=movies --out=action_movies.json --sort='{released: 1}'
```

1.  如果您在当前的中间阶段运行此命令，您将遇到以下错误：

```js
2020-08-17T11:25:51.911+1000    connected to: mongodb+srv://[**REDACTED**]@performancetuning.98afc.gcp.mongodb.net/sample_mflix
2020-08-17T11:25:52.581+1000    Failed: (OperationFailed) Executor error during find command :: caused by :: Sort operation used more than the maximum 33554432 bytes of RAM. Add an index, or specify a smaller limit.
```

这是因为 MongoDB 服务器正在尝试为我们排序大量文档。为了提高导出和导入的性能，您可以限制检索的文档数量，这样 MongoDB 就不必为您排序那么多文档。

1.  添加`--limit`参数以减少被排序的文档数量，并满足三个文档的条件：

```js
mongoexport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/sample_mflix --collection=movies --out=action_movies.json --sort='{released: 1}' --limit=3
```

最后，您需要添加查询参数以过滤掉不属于电影类型的任何文档。

```js
mongoexport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/sample_mflix --collection=movies --out=action_movies.json --sort='{released : 1}' --limit=3 --query="{'genres': 'Action'}"
```

注意

在 MacOS 和 Linux 上，您可能需要更改参数中字符串周围的引号，例如在前面的查询中，您需要使用：`--query='{"genres": "Action"}'`

1.  完成命令后，从`Exercise11.01.txt`文件中将其复制到终端或命令提示符中运行：

```js
2020-08-18T12:35:42.514+1000    connected to: mongodb+srv://[**REDACTED**]@performancetuning.98afc.gcp.mongodb.net/sample_mflix
2020-08-18T12:35:42.906+1000    exported 3 records
```

到目前为止，输出看起来不错，但您需要检查输出文件以确保已导出正确的文档。在您刚刚执行命令的目录中，您应该看到新文件`action_movies.json`。打开此文件并查看其中的内容。

注意

为了提高输出的清晰度，已删除了剧情字段。

您应该看到以下文档：

![图 11.2：action_movies.json 文件的内容（为简洁起见已截断）](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_11_02.jpg)

图 11.2：action_movies.json 文件的内容（为简洁起见已截断）

这个练习说明了以强大和灵活的方式从 MongoDB 导出文档所需的基本知识。结合这里学到的参数，大多数基本导出现在都很容易。要掌握 MongoDB 中的数据导出，保持实验和学习是有帮助的。

# 将数据导入到 MongoDB

现在你知道如何将你的集合数据从 MongoDB 中导出并以易于使用的格式保存到磁盘上。但是假设你在磁盘上有这个文件，并且你想与拥有自己的 MongoDB 数据库的人分享？这种情况下，`mongoimport`就派上用场了。正如你可能从名称中猜到的那样，这个命令本质上是`mongoexport`的反向，并且它被设计为将`mongoexport`的输出作为`mongoimport`的输入。

然而，不仅可以使用从 MongoDB 导出的数据来使用`mongoimport`。该命令支持 JSON、CSV 和 TSV 格式，这意味着从其他应用程序提取的数据或手动创建的数据仍然可以轻松地添加到数据库中。通过支持这些广泛使用的文件格式，该命令成为将大量数据加载到 MongoDB 中的通用方式。

与`mongoexport`一样，`mongoimport`在指定的数据库中操作单个目标集合。这意味着如果你希望将数据导入多个集合，你必须将数据分开成单独的文件。

以下是一个复杂`mongoimport`的例子。我们将在下一节详细介绍语法。

```js
mongoimport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/imports  --collection=oldData --file=old.csv --type=CSV --headerline --ignoreBlanks --drop
```

## 使用 mongoimport

以下是一个具有最少参数的`mongoimport`命令。这比前面的命令简单得多。

```js
mongoimport --db=imports --collection=contacts --file=contacts.json
```

这个例子看起来也与我们在前一节中看到的一些片段非常相似。它几乎与我们的`mongoexport`语法相同，只是不是提供一个使用`--out`创建新文件的位置，而是输入一个`--file`参数，指定我们希望加载的数据。我们的数据库和集合参数与`mongoexport`示例中提供的语法相同。

正如你可能猜到的，`mongoimport`与`mongoexport`共享的另一个相似之处是，默认情况下，它将针对本地计算机上运行的 MongoDB 数据库运行。我们使用相同的`--uri`参数来指定我们正在将数据加载到远程 MongoDB 服务器中——在这种情况下是 MongoDB Atlas。

注意

与`mongoexport`一样，`db`和`uri`参数是互斥的，因为数据库在`uri`中已经定义了。

当使用`--uri`参数时，`mongoimport`命令将如下所示：

```js
mongoimport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlasServer-fawxo.gcp.mongodb.net/imports --collection=contacts --file=contacts.json
```

在你可以执行这个命令来导入你的 MongoDB 数据库之前，你需要一个包含有效数据的文件。现在让我们创建一个。创建可导入数据的最简单方法之一是运行`mongoexport`。然而，为了提高你导入文件的知识，我们将从头开始创建一个。

你可以开始创建一个名为`contacts.json`的文件。在文本编辑器中打开文件并创建一些非常简单的文档。在导入 JSON 文件时，文件中的每一行必须包含一个文档。

`contacts.json`文件应该如下所示：

```js
//contacts.json
{"name": "Aragorn","location": "New Zealand","job": "Park Ranger"}
{"name": "Frodo","location": "New Zealand","job": "Unemployed"}
{"name": "Ned Kelly","location": "Australia","job": "Outlaw"}
```

执行以下导入：

```js
mongoimport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlasServer-fawxo.gcp.mongodb.net/imports --collection=contacts --file=contacts.json
```

这将导致以下输出：

```js
2020-08-17T20:10:38.892+1000    connected to: mongodb+srv://[**REDACTED**]@performancetuning.98afc.g
cp.mongodb.net/imports
2020-08-17T20:10:39.150+1000    3 document(s) imported successfully. 0 document(s) failed to import. 
```

你还可以使用 JSON 数组格式的文件，这意味着你的导入文件包含许多不同的 JSON 文档的数组。在这种情况下，你必须在命令中指定`--jsonArray`选项。这个 JSON 数组结构现在应该对你来说非常熟悉，因为它与`mongoexport`的输出以及你从 MongoDB 查询中收到的结果匹配。例如，如果你的文件包含如下数组：

```js
[
    {
        "name": "Aragorn",
        "location": "New Zealand",
        "job": "Park Ranger"
    },
    {
        "name": "Frodo",
        "location": "New Zealand",
        "job": "Unemployed"
    },
    {
        "name": "Ned Kelly",
        "location": "Australia",
        "job": "Outlaw"
    }
]
```

你仍然可以使用`mongoimport`命令导入文件，并使用`--jsonArray`选项，如下所示：

```js
mongoimport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlasServer-fawxo.gcp.mongodb.net/imports --collection=contacts --file=contacts.json --jsonArray
```

这将导致以下输出：

```js
2020-08-17T20:10:38.892+1000    connected to: mongodb+srv://[**REDACTED**]@performancetuning.98afc.g
cp.mongodb.net/imports
2020-08-17T20:10:39.150+1000    3 document(s) imported successfully. 0 document(s) failed to import. 
```

注意

在上面的示例中，您会注意到可以为导入的文档提供`_id`值。如果没有提供`_id`，则将为文档生成一个。您必须确保您提供的`_id`尚未被使用；否则，`mongoimport`命令将抛出错误。

这两个导入向我们展示了将数据导入 MongoDB 数据库的简单方法，但让我们看看当事情出错时会发生什么。让我们修改文件以为我们的一些文档指定`_id`。

```js
[
    {
        "_id": 1,
        "name": "Aragorn",
        "location": "New Zealand",
        "job": "Park Ranger"
    },
    {
        "name": "Frodo",
        "location": "New Zealand",
        "job": "Unemployed"
    },
    {
        "_id": 2,
        "name": "Ned Kelly",
        "location": "Australia",
        "job": "Outlaw"
    }
]
```

执行一次，您应该可以得到无错误的输出。

```js
mongoimport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlasServer-fawxo.gcp.mongodb.net/imports --collection=contacts --file=contacts.json --jsonArray
```

您将看到以下输出：

```js
2020-08-17T20:12:12.164+1000    connected to: mongodb+srv://[**REDACTED**]@performancetuning.98afc.g
cp.mongodb.net/imports
2020-08-17T20:12:12.404+1000    3 document(s) imported successfully. 0 document(s) failed to import.
```

现在，如果您重新运行相同的命令，您会看到错误，因为该`_id`值已经存在于您的集合中。

```js
2020-08-17T20:12:29.742+1000    connected to: mongodb+srv://[**REDACTED**]@performancetuning.98afc.g
cp.mongodb.net/imports
2020-08-17T20:12:29.979+1000    continuing through error: E11000 duplicate key error collection: imp
orts.contacts index: _id_ dup key: { _id: 1 }
2020-08-17T20:12:29.979+1000    continuing through error: E11000 duplicate key error collection: imp
orts.contacts index: _id_ dup key: { _id: 2 }
2020-08-17T20:12:29.979+1000    1 document(s) imported successfully. 2 document(s) failed to import.
```

您可以在输出中看到错误。您可能还注意到，没有问题的文档仍然成功导入。如果您导入了一个包含一万个文档的文件，`mongoimport`不会因为单个文档而失败。

假设您确实想要更新此文档而不更改其`_id`。您无法使用此`mongoimport`命令，因为每次都会收到重复键错误。

您可以使用 mongo shell 登录 MongoDB 并在导入之前手动删除此文档，但这将是一个缓慢的方法。使用`mongoimport`，我们可以使用`--drop`选项在导入之前删除集合。这是确保文件中存在的内容也存在于集合中的好方法。

例如，假设在我们导入之前，我们的集合中有以下文档：

```js
MongoDB Enterprise PerformanceTuning-shard-0:PRIMARY> db.contacts.find({})
{ "_id" : ObjectId("5e0c1db3fa8335898940129ca8"), "name": "John Smith"}
{ "_id" : ObjectId("5e0c1db3fa8335898940129ca8"), "name": "Jane Doe"}
{ "_id" : ObjectId("5e0c1db3fa8335898940129ca8"), "name": "May Sue"}
```

现在，使用`--drop`运行以下`mongoimport`命令：

```js
mongoimport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlasServer-fawxo.gcp.mongodb.net/imports --collection=contacts –-file=contacts.json --jsonArray --drop
2020-08-17T20:16:08.280+1000    connected to: mongodb+srv://[**REDACTED**]@performancetuning.98afc.g
cp.mongodb.net/imports
2020-08-17T20:16:08.394+1000    dropping: imports.contacts
2020-08-17T20:16:08.670+1000    3 document(s) imported successfully. 0 document(s) failed to import.  
```

执行命令后，您将看到集合中有以下文档，可以使用 find 命令查看这些文档。

```js
db.contacts.find({})
```

您应该看到以下输出：

```js
{ "_id" : ObjectId("5f3a58e8fd0803fc3dec8cbf"), "name" : "Frodo", "location" : "New Zealand", "job" : "Unemployed" }
{ "_id" : 1, "name" : "Aragorn", "location" : "New Zealand", "job" : "Park Ranger" }
{ "_id" : 2, "name" : "Ned Kelly", "location" : "Australia", "job" : "Outlaw" }
```

在下一节中，我们将看看可以与`mongoimport`一起使用的选项。

## mongoimport 选项

现在我们知道了使用`mongoimport`的基本选项，包括`--uri`、`--collection`和`--file`参数。但是，就像我们上一节中的`mongoexport`一样，运行命令时可能还有几个其他选项。其中许多选项与`mongoexport`相同。以下列表描述了一些选项及其效果。

+   `--quiet`：这会减少导入的输出消息量。

+   `--drop`：在开始导入之前删除集合。

+   --jsonArray：仅适用于 JSON 类型，指定文件是否为 JSON 数组格式。

+   `--type`：可以是 JSON、CSV 或 TSV，用于指定要导入的文件类型，但默认类型为 JSON。

+   `--ignoreBlanks`：仅适用于 TSV 和 CSV，这将忽略导入文件中的空字段。

+   `--headerline`：仅适用于 TSV 和 CSV，这将假定导入文件的第一行是字段名称列表。

+   `--fields`：仅适用于 TSV 和 CSV，这将为 CSV 和 TSV 格式的文档指定逗号分隔的键列表。只有在没有标题行时才需要。

+   `--stopOnError`：如果指定，导入将在遇到第一个错误时停止。

以下是使用更多这些选项的示例，特别是带有标题行的 CSV 导入。我们还必须忽略空白，以便文档不会获得空白的`_id`值。

这是我们的`.csv`文件，名为`contacts.csv`：

```js
_id,name,location,job
1,Aragorn,New Zealand,Park Ranger
,Frodo,New Zealand,Unemployed
2,Ned Kelly,Australia,Outlaw
```

我们将使用以下命令导入 CSV：

```js
mongoimport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlasServer-fawxo.gcp.mongodb.net/imports --collection=contacts --file=contacts.csv --drop --type=CSV --headerline --ignoreBlanks
2020-08-17T20:22:39.750+1000    connected to: mongodb+srv://[**REDACTED**]@performancetuning.98afc.gcp.mongodb.net/imports
2020-08-17T20:22:39.863+1000    dropping: imports.contacts
2020-08-17T20:22:40.132+1000    3 document(s) imported successfully. 0 document(s) failed to import.
```

上述命令导致我们的集合中有以下文档：

```js
MongoDB Enterprise atlas-nb3biv-shard-0:PRIMARY> db.contacts.find({})
{ "_id" : 2, "name" : "Ned Kelly", "location" : "Australia", "job" : "Outlaw" }
{ "_id" : 1, "name" : "Aragorn", "location" : "New Zealand", "job" : "Park Ranger" }
{ "_id" : ObjectId("5f3a5a6fc67ba81a6d4bcf69"), "name" : "Frodo", "location" : "New Zealand", "job" : "Unemployed" }
```

当然，这些只是您可能遇到的一些常见选项。文档中提供了完整的列表。熟悉这些选项是有用的，以防您需要对不同配置的 MongoDB 服务器运行更高级的导入。

## 练习 11.02：将数据加载到 MongoDB 中

在这种情况下，您已经成功地在本地机器上创建了客户数据的导出。您已经在不同版本的新服务器上设置了一个新服务器，并希望确保数据正确地导入到新配置中。此外，您还从另一个较旧的数据库中以 CSV 格式获得了一些数据文件，这些数据文件将迁移到新的 MongoDB 服务器。您希望确保这种不同的格式也能正确导入。考虑到这一点，您的目标是将两个文件（如下所示）导入到 Atlas 数据库中，并测试文档是否存在于正确的集合中。

在这个练习中，您将使用`mongoimport`将两个文件（`old.csv`和`new.json`）导入到两个单独的集合（`oldData`和`newData`），并使用 drop 来确保没有剩余的文档存在。

可以通过执行以下步骤来实现这个目标：

1.  微调您的导入并保存以备后用。创建一个名为`Exercise11.02.txt`的新文件来存储您的导出命令。

1.  创建包含要导入的数据的`old.csv`和`new.json`文件。可以从 GitHub 上下载文件[`packt.live/2LsgKS3`](https://packt.live/2LsgKS3)，或者将以下内容复制到当前目录中的相同文件中。

`old.csv`文件应如下所示：

```js
_id,title,year,genre
54234,The King of The Bracelets,1999,Fantasy
6521,Knife Runner,1977,Science Fiction
124124,Kingzilla,1543,Horror
64532,Casabianca,1942,Drama
23214,Skyhog Day,1882,Comedy
```

`new.json`文件应如下所示：

```js
[
    {"_id": 54234,"title": "The King of The Bracelets","year": 1999,"genre": "Fantasy"},
    {"_id": 6521, "title": "Knife Runner","year": 1977,"genre": "Science Fiction"},
    {"_id": 124124,"title": "Kingzilla","year": 1543,"genre": "Horror"},
    {"_id": 64532,"title": "Casabianca","year": 1942,"genre": "Drama"},
    {"_id": 23214,"title": "Skyhog Day","year": 1882,"genre": "Comedy"}
]
```

1.  将标准的`mongoimport`语法输入到您的`Exercise11.02.txt`文件中，只包括 URI、集合和文件位置。首先将您的数据导入到`"imports"`数据库中，先导入旧数据：

```js
mongoimport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/imports --collection=oldData --file=old.csv
```

1.  现在，开始添加额外的参数以满足 CSV 文件的条件。指定`type=CSV`：

```js
mongoimport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/ imports  --collection=oldData --file=old.csv --type=CSV
```

1.  接下来，因为旧数据中有标题行，所以使用`headerline`参数。

```js
mongoimport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/imports  --collection=oldData --file=old.csv --type=CSV --headerline
```

1.  在本章的一些示例中，当您看到 CSV 导入时，使用了`--ignoreBlanks`参数来确保空字段不被导入。这是一个很好的做法，所以在这里也要添加它。

```js
mongoimport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/imports  --collection=oldData --file=old.csv --type=CSV --headerline --ignoreBlanks
```

1.  最后，在这个练习中，您需要确保不要在现有数据之上进行导入，因为这可能会导致冲突。为了确保您的数据被干净地导入，请使用`--drop`参数如下：

```js
mongoimport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/imports  --collection=oldData --file=old.csv --type=CSV --headerline --ignoreBlanks --drop
```

1.  这应该是你进行 CSV 导入所需要的一切。通过复制现有命令到新行，然后删除 CSV 特定参数来开始编写 JSON 导入。

```js
mongoimport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/imports  --collection=oldData --file=old.csv --drop
```

1.  现在，通过以下命令更改`file`和`collection`参数，将您的`new.json`文件导入到`newData`集合中：

```js
mongoimport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/imports  --drop --collection=newData --file=new.json 
```

1.  您可以看到`new.json`文件中的数据是以 JSON 数组格式，因此添加匹配参数如下：

```js
mongoimport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/imports --collection=newData --file=new.json --drop --jsonArray
```

1.  现在，您的`Exercise11.02.txt`文件中应该有以下两个命令。

```js
mongoimport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/imports  --collection=newData --file=new.json --drop --jsonArray
mongoimport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/imports  --collection=oldData --file=old.csv --type=CSV --headerline --ignoreBlanks --drop
```

1.  使用以下命令运行您的`newData`导入：

```js
mongoimport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/imports  --collection=newData --file=new.json --drop --jsonArray
```

输出如下：

```js
2020-08-17T20:25:21.622+1000    connected to: mongodb+srv://[**REDACTED**]@performancetuning.98afc.gcp.mongodb.net/imports
2020-08-17T20:25:21.734+1000    dropping: imports.newData
2020-08-17T20:25:22.019+1000    5 document(s) imported successfully. 0 document(s) failed to import.
```

1.  现在，按照以下方式执行`oldData`导入：

```js
mongoimport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/imports  --collection=oldData --file=old.csv --type=CSV --headerline --ignoreBlanks --drop
```

输出如下：

```js
2020-08-17T20:26:09.588+1000    connected to: mongodb+srv://[**REDACTED**]@performancetuning.98afc.gcp.mongodb.net/imports
2020-08-17T20:26:09.699+1000    dropping: imports.oldData
2020-08-17T20:26:09.958+1000    5 document(s) imported successfully. 0 document(s) failed to import. 
```

1.  通过运行以下命令来检查 MongoDB 中的两个新集合：

```js
show collections
```

输出如下：

![图 11.3：显示新集合](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_11_03.jpg)

图 11.3：显示新集合

首先，我们学会了如何从 MongoDB 服务器中导出数据。现在我们可以使用导入命令将外部数据输入到 MongoDB 中。通过结合这两个简单的命令，我们还可以在 MongoDB 的不同实例之间转移数据，或者在导入到 MongoDB 之前使用外部工具创建数据。

# 备份整个数据库

使用`mongoexport`，理论上我们可以获取整个 MongoDB 服务器，并提取每个数据库和集合中的所有数据。然而，我们必须一次处理一个集合，确保文件正确映射到原始数据库和集合。手动完成这个过程是可能的，但很困难。脚本可以可靠地完成整个 MongoDB 服务器的这项工作，即使有数百个集合。

幸运的是，除了`mongoimport`和`mongoexport`之外，MongoDB 工具包还提供了一个工具，用于导出整个数据库的内容。这个实用程序称为`mongodump`。这个命令创建了整个 MongoDB 实例的备份。您只需要提供 URI（或主机和端口号），`mongodump`命令就会完成剩下的工作。这个导出创建了一个二进制文件，可以使用`mongorestore`来恢复（这是下一节中介绍的命令）。通过结合使用`mongodump`和`mongorestore`，您可以可靠地备份、恢复和迁移 MongoDB 数据库，跨不同的硬件和软件配置。

## 使用 mongodump

以下是一个最简单形式的`mongodump`命令：

```js
mongodump
```

有趣的是，您可以运行`mongodump`而不使用任何参数。这是因为命令需要使用的唯一信息是您的 MongoDB 服务器的位置。如果没有指定 URI 或主机，它将尝试创建运行在您本地系统上的 MongoDB 服务器的备份。

我们可以使用`--uri`参数来指定 URI，以指定我们的 MongoDB 服务器的位置。

注意

与`mongoexport`一样，`--db/--host`和`--uri`参数是互斥的。

然而，如果我们确实有一个本地运行的 MongoDB 服务器，这是我们可能会收到的输出：

```js
2020-08-18T12:38:43.091+1000    writing imports.newData to 
2020-08-18T12:38:43.091+1000    writing imports.contacts to 
2020-08-18T12:38:43.091+1000    writing imports.oldData to 
2020-08-18T12:38:43.310+1000    done dumping imports.newData (5 documents)
2020-08-18T12:38:44.120+1000    done dumping imports.contacts (3 documents)
2020-08-18T12:38:44.120+1000    done dumping imports.oldData (5 documents)
```

在这个命令结束时，我们可以看到我们的目录中有一个新的文件夹，其中包含我们数据库的备份。默认情况下，`mongodump`会导出 MongoDB 服务器中的所有内容。但是，我们可以更加有选择地进行导出，我们将在下一节中看到一个例子。

## mongodump 选项

`mongodump`命令需要非常少的选项才能运行；在大多数情况下，您可能只使用`--uri`参数。但是，我们可以使用几个选项来充分利用这个实用程序命令。以下是一些最有用的选项列表。

+   `--quiet`：这会减少备份时的输出信息量。

+   `--out`：这允许您指定导出的不同位置，以便将其写入磁盘，默认情况下将在运行命令的相同目录中创建一个名为“dump”的目录。

+   `--db`：这允许您指定要备份的单个数据库，默认情况下将备份所有数据库。

+   `--collection`：这允许您指定要备份的单个集合，默认情况下将备份所有集合。

+   `--excludeCollection`：这允许您指定要从备份中排除的集合。

+   `--query`：这允许您指定一个查询文档，将备份的文档限制为仅匹配查询的文档。

+   `--gzip`：如果启用，导出的输出将是一个压缩文件，格式为`.gz`，而不是一个目录。

我们将看看如何创建一个单个数据库的备份，包括用户和角色，并将其保存到磁盘上的特定位置。因为我们正在进行单个数据库的备份，所以可以使用`--uri`来指定要使用的数据库。

```js
mongodump --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/imports --out="./backups"
      2020-08-18T12:39:51.457+1000    writing imports.newData to 
2020-08-18T12:39:51.457+1000    writing imports.contacts to 
2020-08-18T12:39:51.457+1000    writing imports.oldData to 
2020-08-18T12:39:51.697+1000    done dumping imports.newData (5 documents)
2020-08-18T12:39:52.472+1000    done dumping imports.contacts (3 documents)
2020-08-18T12:39:52.493+1000    done dumping imports.oldData (5 documents)
```

正如您在前面的截图中所看到的，只有我们指定的数据库中存在的集合被导出。如果您查看包含我们导出内容的文件夹，甚至可以看到这一点：

```js
╭─ ~/backups
╰─ ls
      imports/
╭─ ~/backups
╰─ ls imports 
      contacts.bson          contacts.metadata.json newData.bson 
      newData.metadata.json  oldData.bson           oldData.metadata.json 
```

您可以在导入目录中看到，对于转储中的每个集合，都创建了两个文件，一个包含我们数据的`.bson`文件，一个用于集合元数据的`.metadata.json`文件。所有`mongodump`的结果都将匹配这种格式。

接下来，使用您的`--query`参数来仅转储集合中的特定文档。您可以使用标准查询文档来指定您的集合。例如，在 Windows 上考虑以下命令：

```js
mongodump --uri=mongodb+srv://USERNAME:PASSWORD@myAtlasServer-fawxo.gcp.mongodb.net/sample_mflix --collection="movies" --out="./backups" --query="{genres: 'Action'}"
```

在 MacOS/Linux 上，您将不得不修改引号如下：

```js
mongodump --uri=mongodb+srv://USERNAME:PASSWORD@myAtlasServer-fawxo.gcp.mongodb.net/sample_mflix --collection="movies" --out="./backups" --query='{"genres": "Action"}'
```

输出如下：

```js
2020-08-18T12:57:06.533+1000    writing sample_mflix.movies to 
2020-08-18T12:57:07.258+1000    sample_mflix.movies  101
2020-08-18T12:57:09.109+1000    sample_mflix.movies  2539
2020-08-18T12:57:09.110+1000    done dumping sample_mflix.movies (2539 documents)
```

电影收藏中有超过 20,000 个文档，但我们只导出了`2539`个匹配的文档。

现在，执行相同的导出，但不使用`--query`参数：

```js
mongodump --uri=mongodb+srv://USERNAME:PASSWORD@myAtlasServer-fawxo.gcp.mongodb.net/sample_mflix --collection="movies" --out="./backups"
```

输出如下：

```js
2020-08-18T12:57:45.263+1000    writing sample_mflix.movies to 
2020-08-18T12:57:45.900+1000    [........................]  sample_mflix.movies  101/23531  (0.4%)
2020-08-18T12:57:48.891+1000    [........................]  sample_mflix.movies  101/23531  (0.4%)
2020-08-18T12:57:51.894+1000    [##########..............]  sample_mflix.movies  10564/23531  (44.9%
)
2020-08-18T12:57:54.895+1000    [##########..............]  sample_mflix.movies  10564/23531  (44.9%)
2020-08-18T12:57:57.550+1000    [########################]  sample_mflix.movies  23531/23531  (100.0%)
2020-08-18T12:57:57.550+1000    done dumping sample_mflix.movies (23531 documents)
```

我们可以在前面的输出中看到，如果没有`--query`参数，导出的文档数量会显著增加，这意味着我们已经将从我们的集合中导出的文档数量减少到仅与查询匹配的文档。

与我们之前学习的命令一样，这些选项只代表您可以提供给`mongodump`的参数的一小部分。通过组合和尝试这些选项，您将能够为您的 MongoDB 服务器创建一个强大的备份和快照解决方案。

通过使用`mongoimport`和`mongoexport`，您已经能够轻松地将特定集合导入和导出数据库。然而，作为 MongoDB 服务器的备份策略的一部分，您可能希望备份整个 MongoDB 数据库的状态。在下一个练习中，我们将仅创建`sample_mflix`数据库的转储，而不是创建我们的 MongoDB 服务器中可能有的许多不同数据库的更大的转储。

## 练习 11.03：备份 MongoDB

在这个练习中，您将使用`mongodump`来创建`sample_mflix`数据库的备份。将数据导出到名为`movies_backup`的文件夹中的`.gz`文件。

完成此练习，执行以下步骤：

1.  为了调整您的导入并将其保存以备后用，创建一个名为`Exercise11.03.txt`的新文件来存储您的`mongodump`命令。

1.  接下来，输入标准的`mongodump`语法，只设置`--uri`参数。记住，`--uri`包含目标数据库。

```js
mongodump --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/sample_mflix
```

1.  接下来，添加指定转储位置的参数。在这种情况下，那就是一个名为`movies_backup`的文件夹：

```js
mongodump --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/sample_mflix --out=movies_backup
```

1.  最后，为了自动将您的转储文件放入`.gz`文件中，使用`--gzip`参数并运行命令。

```js
mongodump --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/sample_mflix --out=movies_backup --gzip
```

注意

因为这个命令将转储整个`sample_mflix`数据库，所以根据您的互联网连接速度，可能需要一点时间。

一旦命令执行，您应该看到类似以下截图的输出：

![图 11.4：执行`mongodump`命令后的输出](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_11_04.jpg)

图 11.4：执行`mongodump`命令后的输出

1.  检查您的转储目录。您可以看到所有的`mongodump`数据都已经写入了正确的目录。

```js
╰─ ls movies_backup
      sample_mflix/
╰─ ls movies_backup/sample_mflix
      comments.bson.gz                   comments.metadata.json.gz
      most_commented_movies.bson.gz       most_commented_movies.metadata.json.gz 
      movies.bson.gz                      movies.metadata.json.gz
      movies_top_romance.bson.gz          movies_top_romance.metadata.json.gz
      sessions.bson.gz                    sessions.metadata.json.gz
      theaters.bson.gz                    theaters.metadata.json.gz
      users.bson.gz                       users.metadata.json.gz
```

在本练习过程中，您已经学会了如何编写一个`mongodump`命令，可以正确地创建数据库的压缩备份。现在，您将能够将这种技术作为数据库迁移或备份策略的一部分。

# 恢复 MongoDB 数据库

在前一节中，我们学习了如何使用`mongodump`创建整个 MongoDB 数据库的备份。然而，除非我们拥有一种将它们加载回 MongoDB 服务器的方法，否则这些导出对我们的备份策略没有好处。通过将我们的导出放回数据库的命令是`mongorestore`。

与`mongoimport`允许我们将常用格式导入 MongoDB 不同，`mongorestore`仅用于导入`mongodump`的结果。这意味着它最常用于将大部分或全部数据库恢复到特定状态。`mongorestore`命令非常适合在灾难后恢复转储，或者将整个 MongoDB 实例迁移到新配置。

当与我们的其他命令结合使用时，应该清楚`mongorestore`完成了导入和导出的生命周期。通过这三个命令（`mongoimport`，`mongoexport`和`mongodump`），我们已经学会了可以导出集合级别的数据，导入集合级别的数据，导出服务器级别的数据，现在最后，通过`mongorestore`，我们可以导入服务器级别的信息。

## 使用`mongorestore`

与其他命令一样，让我们来看一个`mongorestore`命令的简单实现。

```js
mongorestore .\dump\
```

或者在 MacOS/Linux 上，您可以输入以下内容：

```js
mongorestore ./dump/
```

我们需要传递的唯一必需参数是要还原的转储位置。但是，正如您可能已经从我们的其他命令中猜到的那样，默认情况下，`mongorestore`会尝试将备份还原到本地系统。

注意

转储位置不需要`--parameter`格式，而是可以作为命令的最后一个值传递。

在这里，我们可以再次使用`--uri`参数指定 URI，以指定我们的 MongoDB 服务器的位置。

例如，假设我们确实有一个正在运行的本地 MongoDB 服务器。要完成还原，我们需要之前创建的转储文件。以下是基于*练习 11.03，备份 MongoDB*的转储命令：

```js
mongodump --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/imports --out=./dump
```

如果我们现在使用`--drop`选项对此转储运行`mongorestore`，您可能会看到类似以下的输出：

![图 11.5：使用`--drop`选项运行`mongorestore`后的输出](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_11_05.jpg)

图 11.5：使用`--drop`选项运行`mongorestore`后的输出

正如您所期望的，此输出应该与`mongoimport`的输出最为相似，告诉我们从转储文件中恢复了多少文档和索引。如果您的用例是作为备份策略的一部分进行还原，那么这个简单的命令和最少的参数就是您所需要的。

默认情况下，`mongorestore`会还原目标转储中的每个数据库、集合和文档。如果您希望在还原时更加具体，有几个方便的选项可以让您只还原特定的集合，甚至在还原过程中重命名集合。这些选项的示例将在下一节中提供。

## mongorestore 选项

与`mongodump`一样，`mongorestore`命令可以只使用其基本参数（如`--uri`和转储文件的位置）来满足大多数用例。如果您希望执行更具体类型的还原，可以使用以下一些选项：

+   --quiet：这会减少转储的输出消息量。

+   `--drop`：类似于`mongoimport`，`--drop`选项将在还原之前删除要还原的集合，确保命令运行后不会保留旧数据。

+   `--dryRun`：这允许您查看运行`mongorestore`的输出，而不实际更改数据库中的信息，这是在执行潜在危险操作之前测试命令的绝佳方式。

+   `--stopOnError`：如果启用，一旦发生单个错误，进程就会停止。

+   `--nsInclude`：这个选项允许您定义应从转储文件中导入哪些命名空间（数据库和集合），而不是明确提供数据库和集合。我们将在本章后面看到这个选项的示例。

+   `--nsExclude`：这是`nsInclude`的补充选项，允许您提供一个在还原时不导入的命名空间模式。下一节将提供一个示例。

+   `--nsFrom`：使用与`nsInclude`和`nsExclude`中相同的命名空间模式，此参数可以与`--nsTo`一起使用，提供导出中的命名空间到还原备份中的新命名空间的映射。这允许您在还原过程中更改集合的名称。

现在，让我们看一些使用这些选项的示例。请注意，对于这些示例，我们使用的是前一节创建的转储文件。作为提醒，这是创建此转储文件所需的命令：

```js
mongodump --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/sample_mflix --out=dump
```

首先，假设您有一个从`sample_mflix`数据库创建的完整`mongodump`。以下是还原我们集合的子集所需的命令示例。您可能会注意到参数的格式是`{数据库}.{集合}`，但是您可以使用通配符（`*`）运算符来匹配所有值。在以下示例中，我们包括与命名空间`"sample_mflix.movies"`匹配的任何集合（仅`sample_mflix`数据库的 movies 集合）。

```js
mongorestore --uri=mongodb+srv://USERNAME:PASSWORD@myAtlasServer-fawxo.gcp.mongodb.net --drop --nsInclude="sample_mflix.movies" dump
```

当此命令完成运行时，您应该会看到类似以下的输出：

```js
2020-08-18T13:12:28.204+1000    [###################.....]  sample_mflix.movies  7.53MB/9.06MB  (83.2%)
2020-08-18T13:12:31.203+1000    [#######################.]  sample_mflix.movies  9.04MB/9.06MB  (99.7%)
2020-08-18T13:12:33.896+1000    [########################]  sample_mflix.movies  9.06MB/9.06MB  (100.0%)
2020-08-18T13:12:33.896+1000    no indexes to restore
2020-08-18T13:12:33.902+1000    finished restoring sample_mflix.movies (6017 documents, 0 failures)
2020-08-18T13:12:33.902+1000    6017 document(s) restored successfully. 0 document(s) failed to restore.
```

在输出中，您可以看到只有匹配的命名空间被恢复。现在让我们看一下`nsFrom`和`nsTo`参数如何被用来重命名集合，使用与前面示例相同的格式。我们将在`sample_mflix`数据库中将集合重命名为相同的集合名称，但在一个名为`backup`的新数据库中：

```js
mongorestore --uri=mongodb+srv://USERNAME:PASSWORD@myAtlasServer-fawxo.gcp.mongodb.net --drop --nsFrom="sample_mflix.*" --nsTo="backup.*" dump
```

一旦执行此命令完成，最后几行应该类似于以下内容：

```js
2020-08-18T13:13:54.152+1000    [################........]    backup.movies  6.16MB/9.06MB  (68.0%)
2020-08-18T13:13:54.152+1000
2020-08-18T13:13:56.916+1000    [########################]  backup.comments  4.35MB/4.35MB  (100.0%)
2020-08-18T13:13:56.916+1000    no indexes to restore
2020-08-18T13:13:56.916+1000    finished restoring backup.comments (16017 documents, 0 failures)
2020-08-18T13:13:57.153+1000    [###################.....]  backup.movies  7.53MB/9.06MB  (83.1%)
2020-08-18T13:14:00.152+1000    [#######################.]  backup.movies  9.04MB/9.06MB  (99.7%)
2020-08-18T13:14:02.929+1000    [########################]  backup.movies  9.06MB/9.06MB  (100.0%)
2020-08-18T13:14:02.929+1000    no indexes to restore
2020-08-18T13:14:02.929+1000    finished restoring backup.movies (6017 documents, 0 failures)
2020-08-18T13:14:02.929+1000    23807 document(s) restored successfully. 0 document(s) failed to restore. 
```

现在，如果我们观察一下我们的 MongoDB 数据库中的集合，我们会发现`sample_mflix`集合也存在于名为`backup`的数据库中，例如：

```js
MongoDB Enterprise atlas-nb3biv-shard-0:PRIMARY> use backup
switched to db backup
MongoDB Enterprise atlas-nb3biv-shard-0:PRIMARY> show collections
comments
most_commented_movies
movies
movies_top_romance
sessions
theaters
users
```

最后，让我们快速看一下`dryRun`参数的工作原理。看一下以下命令：

```js
mongorestore --uri=mongodb+srv://USERNAME:PASSWORD@myAtlasServer-fawxo.gcp.mongodb.net --drop --nsFrom="imports.*" --nsTo="backup.*" --dryRun .\dump\
```

您将注意到有一个关于命令准备恢复的输出。但是，它不会加载任何数据。MongoDB 中的基础数据都没有改变。这是确保在执行命令之前，确保命令不会出错的绝佳方法。

`mongorestore`命令完成了我们的四个命令，即`mongoimport`，`mongoexport`，`mongodump`和`mongorestore`。虽然使用`mongorestore`很简单，但如果您的备份策略设置更复杂，您可能需要使用多个选项并参考文档。

## 练习 11.04：恢复 MongoDB 数据

在上一个练习中，您使用`mongodump`创建了`sample_mflix`数据库的备份。作为 MongoDB 服务器的备份策略的一部分，您现在需要将这些数据放回数据库。在这个练习中，假设您从导出的数据库和导入的数据库是不同的数据库。因此，为了向客户证明备份策略有效，您将使用`mongorestore`将该转储数据导入到不同的命名空间中。

注意

在完成此练习之前，您需要从*练习 11.03*，*备份 MongoDB*中创建一个转储。

在这个练习中，您将使用`mongorestore`从上一个练习中创建的`movies_backup`转储中恢复`sample_mflix`数据库，并将每个集合的命名空间更改为`backup_mflix`。

1.  调整您的导入并保存以备后用。创建一个名为`Exercise11.04.txt`的新文件来存储您的恢复命令。

1.  确保*练习 11.03*，*备份 MongoDB*中的`movies_backup`转储也在您当前的目录中。否则，您可以使用以下命令创建一个新的备份：

```js
mongodump --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/sample_mflix --out=./movies_backup --gzip
```

1.  接下来，只需输入标准的`mongorestore`语法，只提供 URI 和转储文件的位置。记住，URI 中包括目标数据库：

```js
mongorestore --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net ./movies_backup
```

1.  由于转储文件是以`gzip`格式，您还需要在恢复命令中添加`--gzip`参数，以便它可以解压数据。

```js
mongorestore --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net --gzip ./movies_backup
```

1.  为了确保恢复结果干净，使用您的`--drop`参数在尝试恢复之前删除相关集合：

```js
mongorestore --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net --gzip --drop ./movies_backup
```

1.  现在，添加修改命名空间的参数。因为您正在恢复`sample_mflix`数据库的转储，所以`"sample_mflix"`将是您的`nsFrom`参数的值：

```js
mongorestore --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net --nsFrom="sample_mflix.*" --gzip --drop ./movies_backup
```

1.  这种用例规定这些集合将被恢复到一个名为`backup_mflix`的数据库中。使用`nsTo`参数提供这个新的命名空间。

```js
mongorestore --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net --nsFrom="sample_mflix.*" --nsTo="backup_mflix.*" --gzip --drop ./movies_backup
```

1.  您的命令现在已经完成。将此代码复制并粘贴到您的终端或命令提示符中并运行。将会有大量输出来显示恢复的进度，但最后，您应该会看到如下输出：

```js
2020-08-18T13:18:08.862+1000    [####################....]  backup_mflix.movies  10.2MB/11.7MB  (86.7%)
2020-08-18T13:18:11.862+1000    [#####################...]  backup_mflix.movies  10.7MB/11.7MB  (90.8%)
2020-08-18T13:18:14.865+1000    [######################..]  backup_mflix.movies  11.1MB/11.7MB  (94.9%)
2020-08-18T13:18:17.866+1000    [#######################.]  backup_mflix.movies  11.6MB/11.7MB  (98.5%)
2020-08-18T13:18:20.217+1000    [########################]  backup_mflix.movies  11.7MB/11.7MB  (100.0%)
2020-08-18T13:18:20.217+1000    restoring indexes for collection backup_mflix.movies from metadata
2020-08-18T13:18:26.389+1000    finished restoring backup_mflix.movies (23531 documents, 0 failures)
2020-08-18T13:18:26.389+1000    75594 document(s) restored successfully. 0 document(s) failed to restore.
```

从输出中可以看出，恢复已完成，将每个现有集合恢复到名为`backup_mflix`的新数据库中。输出甚至会告诉您恢复的一部分写入了多少个文档。例如，`23541`个文档被恢复到`movies`集合中。

现在，如果您使用 mongo shell 登录到服务器，您应该能够看到您新恢复的`backup_mflix`数据库和相关集合，如下所示：

```js
MongoDB Enterprise atlas-nb3biv-shard-0:PRIMARY> use backup_mflix
switched to db backup_mflix
MongoDB Enterprise atlas-nb3biv-shard-0:PRIMARY> show collections
comments
most_commented_movies
movies
movies_top_romance
sessions
theaters
users
```

就是这样。你已经成功地将备份还原到了 MongoDB 服务器中。有了对`mongorestore`的工作知识，你现在可以高效地备份和迁移整个 MongoDB 数据库或服务器。正如本章前面提到的，你也许可以用`mongoimport`来完成同样的任务，但是能够使用`mongodump`和`mongorestore`会让你的任务变得更简单。

通过本章学到的四个关键命令（`mongoexport`，`mongoimport`，`mongodump`和`mongorestore`），你现在应该能够完成大部分与 MongoDB 一起工作时遇到的备份、迁移和还原任务。

## 活动 11.01：MongoDB 中的备份和还原

你的客户（电影公司）已经有了几个每晚运行的脚本，用于导出、导入、备份和还原数据。他们进行备份和导出是为了确保数据有冗余的副本。然而，由于他们对 MongoDB 的经验不足，这些命令并没有正确运行。为了解决这个问题，他们请求你帮助他们优化他们的备份策略。按照以下步骤完成这个活动：

注意

这个活动中的四个命令必须按正确的顺序运行，因为`import`和`restore`命令依赖于`export`和`dump`命令的输出。

1.  按`theaterId`字段，按`theaterId`排序，导出到名为`theaters.csv`的 CSV 文件中：

```js
mongoexport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/sample_mflix --db=sample_mflix --collection=theaters --out="theaters.csv" --type=csv --sort='{theaterId: 1}'
```

1.  将`theaters.csv`文件导入到名为`theaters_import`的新集合中：

```js
mongoimport --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/imports --collection=theaters_import --file=theaters.csv
```

1.  将`theaters`集合以`gzip`格式备份到名为`backups`的文件夹中：

```js
mongodump --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net/sample_mflix --out=./backups –gz --nsExclude=theaters
```

1.  `sample_mflix_backup`：

```js
mongorestore --uri=mongodb+srv://USERNAME:PASSWORD@myAtlas-fawxo.gcp.mongodb.net --from="sample_mflix" --to="backup_mflix_backup" --drop ./backups
```

你的目标是接受客户提供的脚本，确定这些脚本有什么问题，并解决这些问题。你可以在自己的 MongoDB 服务器上测试这些脚本是否正确运行。

你可以通过几种方式完成这个目标，但要记住我们在整个章节中学到的东西，并尝试创建简单、易于使用的代码。以下步骤将帮助你完成这个任务：

1.  目标数据库被指定了两次，尝试移除多余的参数。

1.  重新运行`export`命令。我们缺少一个特定于 CSV 格式的选项。添加这个参数以确保我们导出`theaterId`和 location 字段。

现在看看`import`命令，你应该立即注意到一些缺少的参数，这些参数是 CSV 导入所需的。

1.  首先对于`dump`命令，有一个选项是不正确的；运行命令以获取提示。

1.  其次，`dump`命令中没有`nsInclude`选项，因为这是`mongorestore`的选项。用适用于`mongodump`的适当选项替换它。

1.  在`restore`命令中，有一些选项的名称不正确。修复这些名称。

1.  同样在`restore`命令中，从前一个命令中还原一个`gzip`格式的 dump。在还原命令中添加一个选项来支持这种格式。

1.  最后，在`restore`命令中，查看`nsFrom`和`nsTo`选项的值，并检查它们是否在正确的命名空间格式中。

为了测试你的结果，按顺序运行这四个命令（导出，导入，dump，还原）。

`mongoexport`命令的输出如下：

```js
2020-08-18T13:21:29.778+1000    connected to: mongodb+srv://[**REDACTED**]@performancetuning.98afc.gcp.mongodb.net/sample_mflix
2020-08-18T13:21:30.891+1000    exported 1564 records
```

`mongoimport`命令的输出如下：

```js
2020-08-18T13:22:20.720+1000    connected to: mongodb+srv://[**REDACTED**]@performancetuning.98afc.g
cp.mongodb.net/imports
2020-08-18T13:22:22.817+1000    1564 document(s) imported successfully. 0 document(s) failed to import.
```

`mongodump`命令的输出如下：

![图 11.6 mongodump 命令的输出](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_11_06.jpg)

图 11.6 mongodump 命令的输出

`mongorestore`命令的输出开始如下：

![图 11.7：mongorestore 命令的输出开始](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_11_07.jpg)

图 11.7：mongodump 命令的输出开始

`mongorestore`命令的输出结束如下：

![图 11.8：mongorestore 命令的输出结束](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_11_08.jpg)

图 11.8：mongorestore 命令的输出结束

注意

此活动的解决方案可通过此链接找到。

# 摘要

在这一章中，我们涵盖了四个单独的命令。然而，这四个命令都作为 MongoDB 完整备份和恢复生命周期中的元素。通过结合这些基本命令和它们的高级选项，您现在应该能够确保您负责的任何 MongoDB 服务器在数据损坏、丢失或灾难发生时都能得到适当的快照、备份、导出和恢复。

您可能不负责备份 MongoDB 数据，但这些命令也可以用于各种实用程序。例如，将数据导出为 CSV 格式将非常方便，当尝试以电子表格的形式直观地探索信息，甚至向不熟悉文档模型的同事展示时。通过使用 `mongoimport`，您还可以减少导入非 MongoDB 格式数据所需的手动工作量，以及批量导入来自其他服务器的 MongoDB 数据。

下一章涵盖了数据可视化，这是一个非常重要的概念，可以将 MongoDB 信息转化为易于理解的结果，为业务问题提供洞察和清晰度，并将其整合到演示文稿中，以说服利益相关者对数据中难以解释的趋势产生兴趣。


# 第十二章：数据可视化

概述

本章将向您介绍 MongoDB Charts，它提供了使用来自 MongoDB 数据库的数据创建可视化的最佳方式。您将首先学习 MongoDB Charts 数据可视化引擎的基础知识，然后创建新的仪表板和图表，以了解各种类型图表之间的区别。您还将集成和定制图表与其他外部应用程序。通过本章结束时，您将熟悉 Charts PaaS 云界面的基本概念，并能够执行构建有用图表所需的步骤。

# 介绍

数据的可视化呈现对于报告和商业演示非常有用。在科学、统计学和数学中使用图表进行数据可视化的优势不言而喻。图表可以有效地传达业务决策所需的基本信息，就像电影可以通过运动图像来讲述故事一样。

MongoDB 已经开发了一个名为 MongoDB Charts 的新的集成工具，用于数据可视化。这是一个相对较新的功能，首次发布于 2018 年第二季度。MongoDB Charts 允许用户从 MongoDB 数据库中快速表示数据，而无需使用诸如 Java 或 Python 之类的编程语言编写代码。目前，MongoDB Charts 有两种不同的实现方式：

+   **MongoDB Charts PaaS**（**平台即服务**）：这是指 Charts 的云服务。这个版本的 Charts 与 Atlas 云项目和数据库完全集成。它不需要在客户端进行任何安装，并且在 Atlas 云账户中免费使用。

+   **MongoDB Charts 服务器**：这是指本地安装的 MongoDB Charts 工具。Charts 服务器需要从 MongoDB 下载并安装在一个专用服务器安装中，使用 Docker。本地 Charts 包含在 MongoDB Enterprise Advanced 中，并且本课程不涵盖它。

用户在两个版本的 MongoDB Charts 中可用的功能是相似的。用户只需使用一个简单的浏览器客户端，就可以创建仪表板和各种图表。MongoDB 不断扩展 Charts 工具，每次新发布都会添加新功能和修复应用程序中的错误。

在本章中，我们将考虑这样一个场景：XYZ 组织的员工 John 被指派创建一个仪表板，其中包含来自一个电影集合的数据库的信息。John 是一个经验有限的 MongoDB 初学者。他想知道是否有一种简单的方法可以在不使用编程语言编写代码的情况下构建图形。这就是 MongoDB Charts 发挥作用的地方。首先，我们将学习 MongoDB Charts 中的**菜单和选项卡**。

## 探索菜单和选项卡

要启动 MongoDB Charts GUI 应用程序，用户需要首先登录 Atlas 云 Web 应用程序。MongoDB Charts（PaaS 版本）绑定到一个 Atlas 项目（“每个项目”选项），因此如果有多个 Atlas 项目，用户需要选择当前活动的 Atlas 项目。如前几章所述，Atlas 项目的名称是在创建项目时选择的。对于本章，Atlas 中的项目名称是 Atlas 中的默认项目名称：`Project 0`。如下图所示，在 Atlas Web 应用程序中可以看到`Charts`选项卡：

![图 12.1：图表选项卡](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_01.jpg)

图 12.1：图表选项卡

在第一次使用之前，需要激活 MongoDB Charts 选项。为此，您需要点击“立即激活”按钮来激活 Charts 应用程序，如*图 12.1*所示。激活过程只需要一分钟。在激活过程中，Atlas 应用程序将设置 Charts 并生成创建和运行 Charts 所需的数据库元数据。

如*图 12.1*所示，在 MongoDB Charts 中，每月最大数据传输限制为 1GB，可用于沙盒测试和学习 Charts。一旦达到限制，直到月底 MongoDB Charts 将无法使用。但是，可以通过将免费版服务升级为付费的 Atlas 服务来增加限制。您可以在[`www.mongodb.com/pricing`](https://www.mongodb.com/pricing)找到更多详细信息。

请注意，一旦激活，MongoDB Charts 选项将在 Atlas 项目的整个生命周期内保持激活状态。您将被询问是否希望使用示例数据填充或连接现有的 ATLAS 云中的集群。如果您希望删除 Charts 选项，可以通过转到 Atlas 项目设置来执行。如果您想要为现有项目重新激活全新版本的 Charts，这可能会很有用。然而，删除 Charts 应该谨慎进行，因为它将自动删除云中保存的所有图表和仪表板。一旦激活 Atlas Charts，应用程序将启动，并且可以用于创建图表，如下图所示：

![图 12.2：Charts 应用程序](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_02.jpg)

图 12.2：Charts 应用程序

选项按钮显示在应用程序的左侧：

+   `仪表板`：顾名思义，此选项帮助管理仪表板。仪表板是将不同图表组合成单个页面以用于业务报告目的的集合。

+   `数据源`：使用此选项，您可以管理数据源，这只是对 MongoDB 数据库集合的引用，从中处理数据以显示图表。

+   `图表设置`：此选项允许用户管理图表认证提供程序，并监视 Charts 应用程序的网络带宽使用情况。

注意

返回主 Atlas web 应用程序，您可以在 Charts 应用程序的顶部工具栏中点击`Atlas`标签链接。

## 仪表板

在商业演示中，通常显示与主题相关的信息。主题是一个类别，比如人力资源或房地产。主题显示包含了各自业务领域的所有相关数据指标，但是一个主题领域的数据通常与数据库结构不相关。这就是数据存储在 MongoDB 数据库中的方式。因此，仪表板是一个图表分组功能，当我们需要以集中和有意义的方式为企业呈现数据时使用。

在当前版本的 Charts 中，云应用程序会自动为我们创建一个空白仪表板。默认仪表板的名称为`用户的仪表板`，如*图 12.2*所示，其中`用户`是 Atlas 登录用户名。

您可以删除默认仪表板并为您的业务演示创建其他仪表板。要创建新的仪表板，您可以点击*图 12.2*中显示的`添加仪表板`按钮。将打开一个对话框，在其中您需要添加有关新仪表板的详细信息：

![图 12.3：添加仪表板对话框](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_03.jpg)

图 12.3：添加仪表板对话框

要访问仪表板属性，请点击仪表板框中的`…`按钮，如下图所示：

![图 12.4：仪表板属性下拉菜单](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_04.jpg)

图 12.4：仪表板属性下拉菜单

在仪表板上下文中有一些按钮和选项可用：

+   `编辑标题/描述`：此选项用于更改仪表板的当前标题或描述。

+   `复制仪表板`：此选项将仪表板复制到一个新的仪表板中，名称不同。

+   `删除仪表板`：此选项将从 MongoDB Charts 中删除仪表板。

+   `锁定`：此选项为 Atlas 项目用户分配仪表板权限。对于免费版 Atlas Charts 来说，此选项并不实用，因为 MongoDB 不允许您使用免费版来管理项目用户和团队。

要查看仪表板，请点击仪表板名称链接（例如，“用户的仪表板”）。仪表板将打开并显示其中包含的所有图表。如果没有创建图表，则会显示一个空的仪表板，如下图所示：

![图 12.5：用户的仪表板](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_05.jpg)

图 12.5：用户的仪表板

在本章的后面，我们将介绍如何向我们的仪表板添加图表的步骤。但在我们添加新图表之前，我们必须确保数据库文档可用于我们的图表。这是下一节的主题。

## 数据源

数据源代表 MongoDB 数据库结构和 MongoDB Charts 演示引擎之间的接口。数据源是指向特定数据库集合（或集合）的指针，从中处理数据以创建图表。由于 MongoDB Charts 与 Atlas Web 应用程序集成，所有数据源都配置为连接到 Atlas 数据库部署。因此，数据源包含 Atlas 集群部署的描述、将用于 Charts 的数据库和集合。

数据源还可以在 MongoDB 数据库和 MongoDB Charts 应用程序用户之间提供一定程度的隔离。可以保证数据源不会修改 MongoDB 数据库，因为它们以只读模式访问数据库。没有数据源，Charts 无法访问 MongoDB 数据库中的 JSON 文档。

注意

MongoDB Charts（PaaS 版本）允许数据源仅引用来自 Atlas 云集群部署的数据。因此，不可能从本地 MongoDB 数据库安装创建数据源。在生成新数据源之前，必须将数据库集合和文档上传到 Atlas 数据库集群中。

访问数据源，请点击左侧的“数据源”选项卡，如下图所示：

![图 12.6：数据源选项卡](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_06.jpg)

图 12.6：数据源选项卡

在中间，您可以看到现有数据源的列表，页面右上角有“添加数据源”按钮。

如您所见，在当前版本的 Charts 中，您的应用程序会自动填充一个示例数据源。这个示例数据源的名称是“示例数据：电影”。MongoDB 试图通过提供示例数据源和示例仪表板/图表来简化对 Charts 的快速介绍，以便用户在不学习如何使用 Charts 界面的情况下查看一些图表。

注意

示例数据源“示例数据：电影”不能被用户更改或删除。这是因为示例数据源指向一个特殊的 Atlas 数据库，该数据库对您的项目外部，并且用户无法访问。由于不能保证这个数据源将存在于将来的版本中，您应该忽略这个数据源，并继续操作。

要创建新的数据源，您必须提供连接到云 MongoDB 数据库的连接详细信息。数据源通常指向单个数据库集合。由于您已经熟悉了 MongoDB 数据库结构，因此在 Charts 中创建新数据源应该相对容易。

但是，数据源可能比单个数据库集合更复杂。Charts 用户可以使用更复杂的选项（称为**数据源预处理**）。复杂的数据源包括过滤、连接和聚合等功能。有关预处理功能的更多细节将在本章的后面介绍。目前，让我们专注于在 Charts 中创建新数据源。

要创建数据源，请点击“添加数据源”按钮，如*图 12.6*所示。屏幕上会出现一个带有“添加数据源”向导的新窗口：

![图 12.7：添加数据源窗口](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_07.jpg)

图 12.7：添加数据源窗口

您将看到一个用于 Charts 的云数据库列表（图 12.7）。在免费的 Atlas 中，将有一个`M0`集群可用。正如您所看到的，页脚上写着`从 Charts 到您的集群的连接将是只读的`。这是为了让您放心，数据源不会改变数据库信息。您可以从集群列表中选择`Cluster0`，然后点击`下一步`按钮。

接下来，将显示可用数据库的列表。您可以展开每个数据库，显示其中所有的集合，并从各自的数据库中选择特定的集合，如下截图所示：

图 12.8：选择集合窗口

](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_08.jpg)

图 12.8：选择集合窗口

您可以选择整个数据库，或展开数据库部分并从中选择一个或多个集合。如果选择多个集合（或多个数据库），Atlas 将生成多个数据源——每个数据库集合一个数据源。因此，可以创建多个数据源，而不必多次通过此设置助手。在这种情况下的限制是，所有数据源将指向之前选择的单个数据库集群。

一旦数据源配置并保存，它将出现在列表中，如图 12.9 所示：

图 12.9：数据源选项卡显示配置了 sample_supplies 数据库

](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_09.jpg)

图 12.9：数据源选项卡显示配置了 sample_supplies 数据库

## 练习 12.01：使用数据源

在这个练习中，您将为 Charts 创建新的数据源。这些将在本章后面的示例中再次出现，因此请务必仔细遵循这里的步骤：

注意

请确保您已经在`M0`集群中上传了 Atlas 示例数据，就像本书的前三章中所展示的那样。正如之前解释的，如果没有有效的 MongoDB 数据库集合，就无法定义新的数据源。

1.  在`数据源`选项卡中，点击`添加数据源`，如图 12.6 所示。

1.  选择您自己的集群，如图 12.7 所示。然后，点击下一步：

1.  从数据库列表中，点击`sample_mflix`数据库。如果愿意，可以展开数据库部分，查看`sample_mflix`数据库中所有集合的列表：图 12.10：选择 sample_mflix 数据库

](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_10.jpg)

图 12.10：选择 sample_mflix 数据库

1.  点击`完成`按钮。您应该能够在界面中看到创建的五个额外数据源（每个集合一个），如下图所示：图 12.11：数据源列表已更新

](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_11.jpg)

图 12.11：数据源列表已更新

在这个例子中，您在 MongoDB Charts 中添加了一个新的数据源。

## 数据源权限

复杂的 MongoDB 项目可能有许多开发人员和业务用户与 Charts 一起工作。在这种情况下，创建新数据源的 Atlas 用户可能需要与其他 Atlas 项目用户共享。正如前几章所解释的，Atlas 应用程序可以管理大型 Atlas 部署的多个用户。但是，这个概念不适用于本书中大部分示例所展示的免费的 Atlas 沙盒项目。

一旦用户创建了新的数据源，他们就成为了该数据源的所有者，并可以通过在`数据源`窗口的`Charts`选项卡中点击`ACCESS`按钮与其他项目成员共享它（见图 12.9）。这是来自`M0`免费集群的一个截图示例：

图 12.12：数据源权限窗口

](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_12.jpg)

图 12.12：数据源权限窗口

从前面的截图中可以看出，所有者可以为`Project0`中的`Everyone`启用或禁用`VIEWER`权限。`VIEWER`权限允许用户“使用”数据源来构建他们自己的图表。其他用户不允许修改或删除数据源。

对于大型项目，数据源所有者可以授予特定的 Atlas 组或被邀请参与项目的用户权限。这些高级权限是特定于大型 Atlas 项目的，不在本入门课程中涵盖。

## 构建图表

可以使用图表生成器在 MongoDB Charts 中创建新图表。要启动图表生成器，请打开仪表板。您可以通过单击仪表板选项卡中的`用户仪表板`链接来打开自己的用户仪表板，如*图 12.5*所示。然后，单击`添加图表`按钮。

以下是图表生成器的屏幕截图：

![图 12.13：图表生成器](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_13.jpg)

图 12.13：图表生成器

第一步是选择数据源。`选择数据源`按钮出现在左上角绿色高亮显示。请注意，需要创建并发布有效的数据源，然后才能将其分配给图表。此外，不可能将多个数据源分配给一个图表。默认情况下，图表生成器会检索集合中的所有文档。

有一个选项可以单击`示例模式`单选按钮。此模式使图表仅从数据库中检索一部分文档。关于应在图表生成器中加载的 JSON 文档的最大数量没有规定。例如，如果目标是显示精确的聚合值，那么可能需要检索所有文档。另一方面，如果目标是显示趋势或相关图表，则可能只需要一部分文档。然而，在图表中加载大量数据（超过 1GB）将对图表的性能产生负面影响，因此不鼓励这样做。

### 字段

在图表生成器页面的左侧，您可以看到集合字段的列表：

![图 12.14：图表生成器中的字段区域](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_14.jpg)

图 12.14：图表生成器中的字段区域

每个字段都有一个名称和一个数据类型，正如您在*第二章*，*文档和数据类型*中已经看到的。

以下是图表生成器中的数据类型列表：

+   `A` - 字符串

+   `#` - 数字（整数或浮点数）

+   日期

+   `[]` - 数组

+   `{}` - 子文档

注意

在示例截图（*图 12.14*）中，已选择了`sample_mflix.movies`的电影数据源。

## 图表类型

有各种类型的图表可供选择。它们都可以表示类似的视图。但是，某些图表类型更适合特定的场景或数据库数据类型。以下表格列出了所有图表类型及其各自的功能：

![图 12.15：MongoDB 中的图表类型](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_15.jpg)

图 12.15：MongoDB 中的图表类型

每种图表类型可能有一个或多个子类型，这些子类型是主图表的视觉变化，并且在不同的展示中很有用。由于图表子类型取决于主图表类型，我们将讨论每种图表类型的子类型。

可以从同一菜单中选择图表子类型，就在`图表类型`下方，如下面的屏幕截图所示，用于`条形图`类型：

![图 12.16：条形图子类型](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_16.jpg)

图 12.16：条形图子类型

请注意，如*图 12.16*所示，条形图和柱状图有四种不同的子类型。虽然大多数子类型只是相同图表类型的变体，但某些子类型可能有助于专注于数据的不同方面。例如，`分组`子类型有助于比较不同类别中的值，而`堆叠`有助于查看所有类别的累积值。确定适合您的正确子类型的最简单方法是快速浏览它们。图表引擎将自动以您选择的子类型形式重新显示图表。

在`图表类型`选择菜单下方，有一个子菜单，其中包含其他选项卡，用于定义图表通道或维度。以下屏幕截图显示了这些内容：

![图 12.17：图表通道](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_17.jpg)

图 12.17：图表通道

以下列表简要描述了每个选项卡：

+   `编码`：用于定义图表通道。通道描述了数据如何转换为图表可视化项。不同的图表类型具有不同的编码通道。例如，条形图和折线图具有由笛卡尔坐标表示的通道。

+   `筛选`：用于定义数据筛选。此选项有助于筛选输入文档，因此只有所需的文档被考虑用于图表绘制。如果我们想要从图表中排除非相关数据，这将非常有用。

+   `自定义`：用于定义图表的功能和美学自定义，例如图表颜色和标签。虽然这个选项并非必需，但在图表可读性方面通常会产生很大的差异。

有关通道利用的更详细信息将在本章后面介绍。现在，让我们浏览一些图表类型和实际示例。

## 条形图和柱状图

条形图和柱状图可能是演示中最常用的图表类型。图表的基本格式由一组具有不同高度和厚度值的条形组成，排列在二维图中。

条形图特别适用于表示分类数据的聚合值。因此，条形图的主要用途是数据分类或分类。虽然这份材料不是关于数据科学的全面理论，但简短的介绍将帮助您了解基础知识。以下是分类数据的定义描述：

+   **数据分类**：这涉及可以根据类别或标签进行识别的数据，例如质量（高、平均、低）或颜色（白色、红色、蓝色）。这也可能包括一些不同的数值或用作类别的数字值（而不是值）。

+   **数据分箱**：这意味着根据间隔将数据分组到一个类别中。例如，0 到 9.99 之间的数值可以分组到第一个箱中，10 到 19.99 之间的数值可以分组到第二个箱中，依此类推。通过这种方式，我们可以将许多数值分组到相对较少的类别中。分箱是用于表示统计分析图表的方法，称为直方图。

一旦我们定义了数据类别，我们的二维条形图就可以从那里构建。数据类别将填充图表的一个维度，而计算（聚合）值将填充图表的另一个维度。

## 练习 12.02：创建一个条形图来显示电影

本练习的目标是创建一个条形图，并熟悉 MongoDB Charts 界面菜单和选项：

1.  首先，选择图表类型，然后将字段拖放到“编码”区域。例如，如果您选择图表类型“条形图”和“分组”，您可以在“编码”区域看到 X 轴和 Y 轴。

注意

为此图表选择“sample_mflix.movies 数据源”（左上角下拉菜单）

1.  单击名为“标题”（电影标题）的字段，并将其拖放到“Y 轴”：![图 12.18：将标题字段拖放到 Y 轴](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_18.jpg)

图 12.18：将标题字段拖放到 Y 轴

1.  要限制数值的数量，点击“限制结果”，并在“显示”框中输入`5`。

注意

接受“排序方式”的默认选项，即“值”（见*图 12.17*）。我们将在接下来的章节中解释编码通道的各种选项。

1.  下一步是为 X 轴定义值。展开“奖项”字段子文档，然后单击并拖放“获奖次数”到“X 轴”。保持“聚合”默认设置为“求和”：![图 12.19：将获奖次数字段添加到 X 轴](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_19.jpg)

图 12.19：将获奖次数字段添加到 X 轴

图现在应该会自动出现在图表生成器屏幕的右侧：

![图 12.20：按奖项数量排序的前五部电影](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_20.jpg)

图 12.20：按奖项数量排序的前五部电影

1.  现在，根据数据库字段对条形进行分组。对于此功能，将多个字段添加到`X 轴`通道，同时保持`标题`作为唯一的`Y 轴`值。要在 X 轴上添加第二组值（`分组`条形），请将`提名`拖放到`X 轴`：![图 12.21：将提名字段拖动到 X 轴](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_21.jpg)

图 12.21：将提名字段拖动到 X 轴

然后图表会自动更新，显示每部电影的`提名`和`获奖`：

![图 12.22：条形图显示顶级电影的奖项和提名](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_22.jpg)

图 12.22：条形图显示顶级电影的奖项和提名

如果您想要比较值，这种图表子类型特别有用。在这种情况下，您比较了每部电影的提名和获奖次数。正如您所看到的，这些值是“分组”的。这正是`图表类型`选择菜单中`分组`选项的意思。

如果您更喜欢看到它们“堆叠”而不是分组，那么只需单击“堆叠”按钮（*图 12.21*），图表将自动更新。如果我们想要看到电影奖项提名和获奖的累积总值，这个选项就很有用：

![图 12.23：堆叠条形图的结果（而不是分组）](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_23.jpg)

图 12.23：堆叠条形图的结果（而不是分组）

正如您所看到的，在 MongoDB Charts 中从一个子类型切换到另一个子类型只需要点击一次。结果，图表会自动以新格式重新绘制，而无需任何其他用户输入。一旦我们决定我们的初始子类型选择是否适合我们的演示，这个功能就非常有用。

现在，让我们看看 Atlas 中可用的其他类型的图表。

## 圆形图表

圆形图表是彩色的圆形或半圆形，通常被细分成扇形，以表示值或百分比。圆形图表也是“单维”的，这意味着图表只能表示一组标量值，而不能表示可以在笛卡尔坐标系中表示的值。考虑到这个限制，我们需要意识到使用这种类型的图表可以表示的信息很少。尽管如此，圆形图表通过强调一个扇形与整体之间的比例，提供了数据比例的强大视觉表示。由于其简单性和视觉冲击力，这种类型的图表对于演示也非常有效。

圆形图表有两种子类型：`圆环`和`仪表盘`：

+   `圆环`：这代表一个全彩色的圆（饼），被分成代表值或百分比的扇形。可能有很多值或扇形。然而，建议限制值的数量，以便圆环被分成相对较少的扇形。

+   `仪表盘`：这代表一个半圆，与总数的比例。这种类型的图表是圆环类型的简化版本，因为它可以表示单个值的比例。

在下一个练习中，您将学习如何创建一个圆环图。

## 练习 12.03：从电影收藏创建饼图图表

假设您需要根据电影的原产国来表示电影。由于饼状图通常比表格更直观，您决定使用圆环图来表示这些数据。这也将使您强调世界上产出顶级电影的国家：

1.  从`图表类型`下拉菜单中选择`圆环`子类型：![图 12.24：选择圆环图子类型](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_24.jpg)

图 12.24：选择圆环图子类型

1.  点击并将`国家`字段拖动到`标签`通道，如下图所示：![图 12.25：将国家字段拖动到标签通道](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_25.jpg)

图 12.25：将国家字段拖动到标签通道

1.  单击`选择方法`下拉菜单，然后选择`按索引选择数组元素（索引=0）`以选择所有文档中数组的第一个元素。接受`排序方式`的默认选项——即`值`。

注意

因为`countries`字段是 JSON 数组数据类型，您最好的选择将是`数组缩减`方法，这样 Charts 将知道如何解释数据。在这个例子中，您将专注于主要国家制片商（`索引=0`），并忽略联合制片商。

1.  减少结果数量（使用`限制结果`选项）到`10`。这样，您的饼图将只有`10`个切片，这将对应于前`10`个电影制片商：![图 12.26：将限制结果的值设置为 10](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_26.jpg)

图 12.26：将限制结果的值设置为 10

1.  将`title`字段拖放到`Arc`通道中，并选择`COUNT`选项作为`聚合`下拉菜单的选项。圆形图表应出现在屏幕右侧，如下所示：![图 12.27：顶部电影制片国家的环形图表](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_27.jpg)

图 12.27：顶部电影制片国家的环形图表

这个练习带您完成了构建环形图或饼图所需的几个简单步骤。几乎任何演示文稿或仪表板都包含至少一个饼图，因为它们看起来很吸引人。但吸引力并不是环形图如此受欢迎的唯一原因。环形图也是在视觉图表中表示比率和比例的强大工具。接下来的部分将介绍另一种类型的图表，即地理空间图表。

## 地理空间图表

地理空间图表是一种特殊类别的图表，其中地理数据是构建图表的主要成分。地理（或地理空间）数据的最简单定义是它包含有关地球上特定位置的信息。位置细节被标在地图上以构建地理空间图表。

地理空间信息可以是具体的或更一般的。以下是一些可以使用地图引擎（如 Google Maps）轻松映射的地理空间数据的示例：

+   精确的经度和纬度坐标

+   可以使用地图引擎映射的地址

+   更广泛的位置，如城市、地区或国家

例如，假设我们有一个包含有关汽车信息的数据库。主数据库集合包含数百万个关于汽车的文档，如型号、里程表细节和其他属性。还有一些其他属性将描述车辆注册的物理地址。然后可以使用该信息构建使用城市地图的地理空间图表。

地理空间图表有几种子类型，如下所示：

+   `Choropleth`图表：此图表显示着色的地理区域，如地区和国家。这种类型的图表不太具体，通常用于高级别的聚合，例如显示每个国家的 COVID-19 病例总数的图表。

+   `散点`图表：此图表需要精确的地址或位置。图表在地图上用一个点或一个小圆圈标记位置。如果我们想要显示具有相对较少的精确位置的图表，这个图表是有用的。

+   `热力图`图表：热力图在地图上显示不同强度的颜色。更高的强度对应于该位置的数据库实体的更高密度。热力图图表适用于在地图上显示大量对象的情况，用户更关注密度而不是精确位置。

在下一节中，您将完成一个练习，使用包含样本地理空间信息的`sample_mflix`数据库，以进一步练习在新的地理空间图表中使用地理点信息。

## 练习 12.04：创建地理空间图表

本练习的目的是创建一个地理空间图表，代表美利坚合众国所有电影院的地图。您将使用`theaters`集合来映射地理数据：

1.  对于`数据源`，选择`sample_mflix.theaters`：![图 12.28：选择 sample_mflix.theaters 作为数据源](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_28.jpg)

图 12.28：选择 sample_mflix.theaters 作为数据源

1.  选择`地理空间`图表，并从子类型类别中选择`热力图`：![图 12.29：从地理空间图表子类型列表中选择热力图](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_29.jpg)

图 12.29：从地理空间图表子类型列表中选择热力图

1.  点击`geo`字段，将其拖放到“坐标”编码通道中：![图 12.30：将 geo 字段拖放到坐标编码通道中](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_30.jpg)

图 12.30：将 geo 字段拖放到坐标编码通道中

1.  接下来，点击`theatreId`字段，将其拖放到“强度”通道中：![图 12.31：将 theatreId 字段拖放到强度通道中](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_31.jpg)

图 12.31：将 theatreId 字段拖放到强度通道中

切换到`热力图`图表类型时，您应该注意到立即出现的彩色区域图表更新，而不是点状图表——在美国大城市周围的红色强度。

美国地图应该出现在窗口的右侧，并将使用不同的颜色渐变显示剧院的密度。颜色编码显示在图表的右侧。电影院的最高密度（大约在纽约市附近）将显示为地图上的红色（见*图 12.32*）：

![图 12.32：热力图图表](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_32.jpg)

图 12.32：热力图图表

在这个练习中，您练习了构建美国所有电影院的地理空间图表。您首先进行数据分析，以查看数据库信息是否适合通过地理空间图表进行呈现。一旦数据在 MongoDB 数据库中可用，构建图表就相对容易。

# 复杂图表

在之前的章节中，您已经看到了在 Atlas 中使用 MongoDB Charts 是多么容易。虽然用户界面非常直观和易于使用，但它也非常强大。MongoDB Charts 中有许多选项，可以对数据库中的数据进行预处理、分组和以各种方式显示。在本节中，我们将看一些更高级的配置主题。

## 数据预处理和过滤

如前所述，图表通过在 Charts 中定义的数据源访问数据库。默认情况下，会选择数据库集合中的所有文档来构建新的图表。此外，Charts 中的数据字段将继承原始数据库 JSON 文档的数据格式。

还要注意，数据源不能改变或修改数据库。在现实生活中，经常发生数据格式不适合通过图表进行呈现的情况。数据必须经过准备，或者数据格式在使用图表之前需要以某种方式进行修改。这种用于绘图的数据准备类别称为预处理。

数据预处理包括以下内容：

+   **数据过滤**：过滤数据，只选择某些文档

+   **数据类型更改**：修改数据类型，使其更适合图表生成器

+   **添加新字段**：添加在 MongoDB 数据库中不存在的自定义字段

### 数据过滤

数据过滤允许用户仅选择来自 MongoDB 集合的子集文档。有时，数据库集合太大，这使得图表生成器的操作变得更慢、更不有效。克服这个问题的一种方法是对数据进行抽样。另一种方法是根据某些类别过滤数据，以便仅考虑图表的子集文档。

用户可以通过以下表中列出的几种方式控制图表中处理的文档数量。

![图 12.33：用户可以控制文档数量的方式的文档数量](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_33.jpg)

图 12.33：用户可以控制图表中处理的文档数量的方式

注意

建议选择最适合图表要求的一个过滤器方法，并只使用该过滤器。将两种或三种过滤方法混合到同一个图表中可能会导致混乱，应该避免。

除了**Filter Tab**方法是 UI 的一部分外，所有其他方法都需要使用 JavaScript 代码来定义过滤器。查询语法在*第四章*的*查询文档*中有详细介绍。在 Charts 中也可以使用相同的查询格式。例如，要为所有在 1999 年后发布的意大利或法国电影定义过滤器，可以编写以下 JSON 查询：

```js
{ countries: { $in: ["Italy", "France"]}, 
  year: { $gt : 1999}}
```

一旦将此查询输入到`Query`栏中，应单击`Apply`按钮，如下截图所示：

![图 12.34：查询栏示例截图](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_34.jpg)

图 12.34：查询栏示例截图

注意

过滤文档可能会导致图表响应延迟，特别是在处理大型数据库时。为了提高性能，可以在涉及过滤表达式的集合字段上创建索引，如*第九章*的*性能*中所示。

### 添加自定义字段

Charts 允许用户添加自定义字段，用于构建图表。有时，来自 MongoDB 的原始数据并不提供创建新图表所需的正确属性，因此添加自定义字段变得很重要。这些自定义字段大多是使用源数据库值派生或计算出来的。

可以通过单击图表生成器的`Fields`区域中的`+ Add Field`按钮来添加自定义字段，如下截图所示：

![图 12.35：字段区域中的添加字段按钮](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_35.jpg)

图 12.35：字段区域中的添加字段按钮

可以添加两种类型的字段：

+   `MISSED`：此选项用于添加在字段列表中缺失的字段。例如，想象一下，应用程序中添加了一个新字段，数据库中只有少数文档有这个新字段。在这种情况下，MongoDB Charts 可以将缺失的字段添加到初始加载中。

+   `CALCULATED`：用于添加集合中不存在的新字段。例如，共享乘车应用程序的源数据库可以有关于小时数和每小时费率的字段。但是，总值（小时数乘以费率）可能不在数据库中。因此，我们可以添加一个从数据库中的其他值计算出来的新自定义字段。

注意

如果字段在任何集合文档中不存在，则无法添加`MISSED`字段。在这种情况下，您需要先添加/更新集合文档。

为了更好地理解这个概念，考虑这个实际例子。在这个例子中，您将在 Charts 中添加一个新的计算字段。执行以下步骤：

1.  单击`Add Field`按钮，然后单击`CALCULATED`按钮，如下截图所示：![图 12.36：添加新字段](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_36.jpg)

图 12.36：添加新字段

1.  在`adjusted_rating`中输入新字段名称。

1.  输入计算总值的公式，即`tomatoes.viewer.rating * 1.2`。

1.  单击`Save`按钮。现在应该能够看到新计算字段并在图表中使用它，就像任何其他数据类型属性一样。

注意

计算字段不会保存在数据库中。它们的范围仅限于 MongoDB 图表生成器内。此外，可以从`Fields`列表中删除计算字段。

### 更改字段

有时，从数据库中获取的数据不是正确的数据类型。在这种情况下，MongoDB 图表允许用户将字段更改为适合图表绘制的数据类型。例如，图表通道可能需要数据以数字格式进行聚合“求和”或“平均”。要更改字段，请将鼠标指针拖动到“字段”列表中的字段名称上（在“图表构建器”窗口的左侧）：

![图 12.37：从 fullplot 字段中选择转换类型](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_37.jpg)

图 12.37：从 fullplot 字段中选择转换类型

单击`...`菜单并选择“转换类型”选项（唯一可用的选项），将显示 JSON 数据类型列表。然后，您可以选择所需的数据类型，然后单击“保存”按钮。

例如，如果要将`metacritic`数字字段（`#`）更改为字符串字段（`A`），可以单击`metacritic`，然后将显示一个新的“转换类型”窗口，如下所示：

![图 12.38：转换类型窗口](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_38.jpg)

图 12.38：转换类型窗口

请注意，更改字段的数据类型只会对当前图表产生影响，并不会更改数据库中的数据类型。

注意

在最新版本的图表中，上下文字段菜单[`…`]中还有另一个选项，称为“查找”。 “查找”字段允许我们通过连接同一数据库中的第二个集合来构建图表。有关如何连接集合的详细信息，请参阅*第四章*，*查询文档*。

# 通道

编码通道是数据可视化中最重要的方面之一。通道决定了数据在图表中的可视化方式。如果选择了错误的通道类型，用户可能会得到混乱的图表或完全意想不到的结果。因此，对编码通道的正确理解对于高效的图表构建和数据可视化至关重要。

如前面的示例所示，编码通道位于图表构建器的“编码”选项卡下方，就在图表子类型选择按钮的下方：

![图 12.39：编码通道](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_39.jpg)

图 12.39：编码通道

每个编码通道都有一个名称和类型。通道名称定义了图表中的目标，即通道将用于的终点。例如，“X 轴”通道名称表示该通道提供了图表的水平轴的值。在这种情况下，我们将会得到一个笛卡尔二维图表是很清楚的。通道类型定义了通道输入所期望的数据类型。找到通道输入的正确数据类型很重要。另外，您现在可能已经注意到，并非所有数据类型都可以被接受为通道输入。

MongoDB 图表中有四种通道类型，如下表所示：

![图 12.40：MongoDB 图表中的通道类型列表](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_40.jpg)

图 12.40：MongoDB 图表中的通道类型列表

注意

可以从 JSON 文档中的子文档或数组字段中分配通道值。在这种情况下，MongoDB 图表将要求您标识用于通道编码的元素，例如，数组索引`[0]`（指向每个文档中数组的第一个元素）。

## 聚合和分箱

一个通道中的数据通常与类别数据类型通道结合在一起，以便它可以计算每个类别的聚合值。例如，我们可以对法国电影的所有奖项进行“求和”聚合。在图表构建器中，当将字段拖放到聚合通道中时，假定值将在图表中进行聚合。图表构建器会在不需要您编写聚合管道代码的情况下透明地执行此操作。

聚合类型将取决于我们在通道输入上提供的数据类型。例如，如果通道提供的数据类型是文本，则不可能进行“求和”操作。

有几种聚合类型，如下表所示：

![图 12.41：聚合类型](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_41.jpg)

图 12.41：聚合类型

注意

一些通道可以有“系列”类型。这个选项允许用户向图表添加第二个维度，无论是唯一的还是分组的，都可以通过将数据分组在一系列值中来实现。

## 练习 12.05：为柱状图分组值

在这个练习中，您将构建另一个柱状图，显示在意大利制作的电影。在这个图表中，您需要按电影发行年份对数据进行聚合。此外，图表应该只考虑 1970 年后发布的电影。为了构建这个图表，您需要过滤文档并选择编码字段来表示按年份聚合的电影。以下步骤将帮助您完成这个练习：

1.  从仪表板窗口中，单击“添加图表”，然后选择“柱状图”类型。

1.  将“年份”字段拖放到分类通道“Y 轴”上。图表生成器将检测到有太多的分类不同值（年份），并建议对它们进行分组（将它们分组为 10 年期）。现在，切换“分组”并为“分组大小”输入值`10`（见下图）：![图 12.42：输入 10 作为分组大小的值](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_42.jpg)

图 12.42：输入 10 作为分组大小的值

1.  将“标题”字段拖放到分类通道“X 轴”上。然后，选择“聚合”函数选项“计数”并单击“筛选”选项卡。

1.  将“国家”字段拖放到图表筛选器中。

1.  如下所示，从图表筛选器中选择“意大利”：![图 12.43：从国家列表中选择意大利](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_43.jpg)

图 12.43：从国家列表中选择意大利

1.  将第二个字段“年份”拖放到图表筛选器中，并将“最小值”设置为`1970`，如下所示：![图 12.44：选择 1970 作为年份字段的最小值](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_44.jpg)

图 12.44：将 1970 年作为年份字段的最小值

1.  将图表标题编辑为“意大利电影”，如下所示：![图 12.45：最终意大利电影柱状图](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_45.jpg)

图 12.45：意大利电影最终柱状图

1.  保存图表。

在这个练习中，您以简单的方式使用过滤和聚合技术创建了一个图表，而且没有编写任何 JavaScript 代码。新图表已保存在仪表板上，因此可以在以后加载和编辑。MongoDB 图表生成器具有高效的 Web GUI，可帮助用户创建复杂的图表。除了易于使用外，界面还有许多选项和配置项可供选择。

# 集成

到目前为止，本章的主题集中在描述 MongoDB 图表 PaaS 的功能上。我们已经了解到用户可以轻松地使用来自 Atlas 云数据库的数据源构建仪表板和图表。本章的最后一个主题涉及 MongoDB 图表的最终结果，即仪表板和图表如何用于演示和应用程序。

一种选择是将图表保存为图像并将其集成到 MS PowerPoint 演示文稿中，或将其发布为网页内容。虽然这个选项非常简单，但它有一个主要缺点，即图表图像是静态的。因此，当数据库更新时，图表不会更新。

另一个选择是将 MongoDB 图表用作演示工具。这个选项保证了图表在数据库更新时会刷新和渲染。然而，这个选项可能不是理想的，因为内容仅限于 MongoDB 图表用户界面，无法轻松集成。

幸运的是，MongoDB 图表有一个选项，可以将图表发布为网页和 Web 应用程序的动态内容。它也可以轻松集成到 MS PowerPoint 演示文稿中。这个集成功能称为**嵌入式图表**，允许图表在预先设定的时间间隔后自动刷新。

## 嵌入式图表

嵌入图表是一种选项，您可以使用它来通过提供可用于数据演示和应用程序的网页链接来共享 MongoDB Charts 工具之外的图表。

有三种方法可以共享图表：

+   `未经身份验证`：使用此方法，用户无需进行身份验证即可访问图表。他们只需要访问链接。这个选项适用于公共数据或不敏感的信息。

+   `已验证`：使用此方法，用户需要进行身份验证才能访问图表。这个选项适用于具有非公开数据的图表。

+   `验证签名`：使用此方法，用户需要提供签名密钥才能访问图表。这个选项适用于敏感数据，需要额外的配置和代码来验证签名。

选择方法取决于数据安全要求和政策。`未经身份验证`方法适用于学习或测试非敏感数据。在具有真实或敏感数据的应用程序中，应始终使用`验证签名`方法与其他应用程序集成。

如此屏幕截图所示，嵌入图表有几个选项：

![图 12.46：嵌入图表窗口](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_46.jpg)

图 12.46：嵌入图表窗口

例如，假设您想要为用户配置`未经身份验证`访问。选择`未经身份验证`选项后，您可以指定以下详细信息：

+   `用户指定的过滤器（可选）`：您可以指定在共享时不可见的字段。

+   `自动刷新`：您可以指定图表自动刷新的时间间隔。

+   `主题`：您可以指定`浅色`或`深色`的图表主题。

嵌入代码会自动生成，并可以像*图 12.46*中所示一样复制到应用程序代码中。

## 练习 12.06：将图表添加到 HTML 页面

在本练习中，您将创建一个包含使用 MongoDB Atlas Charts 创建的嵌入图表的简单 HTML 报告。使用在*练习 12.05*中创建的保存图表`意大利电影`，*为条形图分箱值*：

1.  与前面的部分一样，通过转到`数据源`选项卡并选择数据源`sample_mflix.movies`来启用对数据源的访问。

1.  点击菜单右侧的(`…`)，选择`外部共享选项`。

1.  点击`未经身份验证或已验证访问`，然后点击`保存`，如下图所示：![图 12.47：外部共享选项截图](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_47.jpg)

图 12.47：外部共享选项截图

1.  转到`仪表板`选项卡，打开`电影`仪表板。您应该能够看到创建和保存的图表，包括`意大利电影`条形图。

1.  点击图表右侧的(`…`)，然后点击`嵌入图表`，如下图所示：![图 12.48：选择嵌入图表选项](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_48.jpg)

图 12.48：选择嵌入图表选项

`嵌入图表`窗口将如下图所示出现：

![图 12.49：嵌入图表页面](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_49.jpg)

图 12.49：嵌入图表页面

1.  点击`未经身份验证`选项卡，并按以下设置更改设置：

`自动刷新`：`1 分钟`

`主题`：`浅色`

1.  复制出现在页面底部的`嵌入代码`内容。

注

用户可以通过选择过滤器与嵌入的图表进行交互。要激活此可选功能，请点击`用户指定的过滤器（可选）`，并选择可用于确定图表过滤器的字段。JavaScript SDK 允许使用编码库集成 MongoDB 图表。这个选项是由开发人员驱动的，并且在本章中没有介绍。

1.  使用诸如记事本之类的文本编辑器创建一个简单的 HTML 页面，并将其保存为`.html`扩展名。

```js
<hr />
<h3 style="text-align: left;">Introduction to MongoDB - Test HTML&nbsp;</h3>
<p align="center">
<! – Paste here the embedded code copied from MongoDB Chart -- >
</p>
<h3 style="text-align: center;">&nbsp;</h3>
<hr />
<p>&nbsp;</p>
```

1.  现在，考虑以下代码行：

```js
<!-- Paste here the embedded code copied from MongoDB chart -->
```

1.  在其位置上，添加在*步骤 7*中复制的代码。最终代码结果应如下所示：

```js
<hr />
<h3 style="text-align: left;">Introduction to MongoDB - Test HTML&nbsp;</h3>
<p align="center">
<iframe style="background: #FFFFFF;border: none;border-radius: 2px;box-  shadow: 0 2px 10px 0 rgba(70, 76, 79, .2);" width="640" height="480"     src="img/charts?id=772fcf16-f0ec-467d-b2bf-        d6a49e665511&tenant=e6ffce97-1ff7-4430-9bb2-          8b8fb32917c5&theme=light"></iframe>
</p>
<h3 style="text-align: center;">&nbsp;</h3>
<hr />
<p>&nbsp;</p>
```

1.  保存记事本文件。然后，使用互联网浏览器（如 Google Chrome 或 Microsoft Edge）打开该文件。浏览器应该显示具有动态图表内容的页面，如下面的屏幕截图所示：![图 12.50：浏览器视图](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_50.jpg)

图 12.50：浏览器视图

这个练习是 MongoDB 图表如何集成到 HTML 网页中的一个很好的例子，这样内容在数据变化时可以动态更新。在这种情况下，如果数据库记录被更新并且图表被改变，网页也将在 1 分钟的间隔后更新，以反映这些变化。

在本节中，我们已经讨论了图表展示和与外部应用集成的选项。在大多数业务用例中，静态图像不适用于动态网页内容和应用程序。MongoDB 的`嵌入图表`选项允许用户在演示文稿和 Web 应用程序中集成图表。安全和非安全的图表发布选项都是可用的。然而，对于数据敏感的演示文稿，应始终使用安全选项。

## 活动 12.01：创建销售演示仪表板

在这个活动中，您将从样本数据库中创建一个新的销售统计图表。具体来说，分析必须帮助确定科罗拉多州丹佛市的销售，基于销售项目类型。以下步骤将帮助您完成此活动：

1.  创建一个甜甜圈图表，以绘制每个销售项目的销售总额。

1.  从`sample_supplies`数据库创建一个新的数据源。

1.  过滤数据，使报告中只考虑来自丹佛商店的文档。图表应显示一个甜甜圈，显示前 10 个项目（按价值），并应命名为`丹佛销售（百万美元）`。

1.  使用图表标签格式化以显示以百万为单位的值，并根据生成的图表解释数据。

最终输出应如下所示：

![图 12.51：销售图表](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_12_51.jpg)

图 12.51：销售图表

注意

此活动的解决方案可以通过此链接找到。

# 总结

这一章与以往的章节不同，它侧重于图表用户界面而不是 MongoDB 编程。使用 Atlas 云图表模块可以实现令人印象深刻的结果，使用户能够专注于数据而不是编程和演示。

有各种图表类型和子类型可供选择，这使得图表更加有效且更易于使用。MongoDB 图表还可以很容易地使用`EMBED CODE`选项与其他 Web 应用程序集成，这对开发人员来说是一个优势，因为他们不需要处理另一个编程模块来在他们的应用程序中绘制图表。在下一章中，我们将看一个业务用例，其中 MongoDB 将用于管理后端。


# 第十三章：MongoDB 案例研究

概述

在本章中，您将学习 MongoDB 如何在商业用例中使用。它以一个场景开始，虚构的市政府和当地初创企业共同开发了一个基于移动应用的共享单车平台。然后，它将涵盖一个详细的项目提案和一些挑战，以及如何使用基于 MongoDB Atlas 的数据库即服务解决方案解决这些挑战。最后，您将探索 MongoDB 如何用于一些用例，逐个进行了解，并验证数据库设计是否涵盖了所有需求。

# 介绍

到目前为止，在本书中，我们已经成功掌握了 MongoDB 的各个方面，从基本介绍到灾难恢复。对于您选择学习的任何工具或技术，了解其如何使用是很重要的，这就是我们在前几章中所取得的成就。因此，最后一章将专注于使用这项技术来解决现实生活中的问题，并使生活更加轻松。

在本章中，我们将研究一个虚构的市政府及其即将推出的共享单车项目的用例。首先，我们将了解项目的细节并看看为什么需要它；然后，我们将涵盖需求并找出 MongoDB 如何解决他们的问题。

# Fair Bay 市政厅

Fair Bay 是位于北罗斯兰东海岸的城市，以其宜人的气候和历史意义而闻名。它也是该国的主要商业中心之一。在过去的二十年里，这座城市创造了巨大的就业机会，并吸引了来自全国和全球各地的人才。因此，过去十年间，这座城市的人口急剧增加，进而推动了城市的房地产市场。

城市正在快速扩张，当地市政府正在努力评估和重新开发城市的基础设施和设施，以维持其生活指数的便利性。他们经常对其公共基础设施进行调查和评估，以确定公众提出的一些最常见的问题。

在过去的评估和调查中，当地社区居民反复提出了以下关切：

+   当地交通总是拥挤。

+   交通拥堵频繁发生。

+   燃油和停车价格不断上涨。

+   城市中心的空气质量很差。

+   通勤时间正在增加。

为了解决这些投诉，市政府邀请公司、初创企业，甚至公众提出智能和创新的想法和相关项目提案。经过仔细审查和批准，最佳提案被送交州发展和规划委员会审批资金。市政府的倡议迄今为止取得了巨大成功，因为他们有几个受欢迎的想法。今年，提交的项目提案之一引起了大家的注意。当地一家初创企业提出了一个在线共享单车平台 Fair Bay City Bikes 的推出。除了是独特的创新解决方案外，它也是最环保的项目提案之一。他们的提案细节在以下部分中概述。

# Fair Bay City Bikes

人口稠密的大都市经常遭受交通拥堵和公共交通拥挤。共享单车计划是一种可持续的出行方式，有几个原因。它提供了比使用汽车、公共交通或私人自行车更健康和更便宜的交通方式。它涉及在城市各地采购和停放自行车。这些自行车可以由公众使用，按先到先得的原则，进入城市。通常，自行车的预订和跟踪是通过在线平台控制的。研究和调查得出结论，一个良好实施的共享单车计划可以：

+   减少交通拥堵

+   改善空气质量

+   减少汽车和公共交通的使用

+   帮助人们节省在其他交通工具上的花费

+   鼓励更健康的生活方式

+   增进社区感

因此，许多城市正在通过提供共享单车平台和城市内的专用自行车道来积极鼓励骑自行车。Fair Bay City Bikes 项目是一个具有独特特点的下一代共享单车平台，如自动锁定和用户友好的移动应用程序。接下来，我们将看一下他们提案的一些主要亮点。

## 提案亮点

Fair Bay City Bikes 项目的一些亮点如下。

### 无桩自行车

Fair Bay City Bike 项目是一个无桩共享单车项目。一般来说，自行车需要专用的停车站来锁定。用户需要访问这些停车站来开始和结束他们的骑行。这种系统的主要缺点是在城市各地均匀设置停车站基础设施。建立这样的网络涉及在每个地区找到一个安全和合适的地方，这通常是负担不起的。其次，人们往往很难找到和访问停车站。对用户来说，找不到靠近目的地的空停车站是一个常见的问题，这让他们不愿使用该系统。

另一方面，无桩自行车具有内置的自动锁定和解锁机制。它们可以在任何安全的地方或任何专用停车区取车、停车和留下。用户可以在其周围停放的任何自行车中选择，并将它们留在靠近目的地的任何安全停车位。

### 易于使用

用户可以在他们的手机上下载并访问 City Bikes 应用程序。在提供一些个人信息，如姓名、电话号码和政府发行的照片 ID（如驾驶执照）后，他们就可以随时使用自行车。

用户可以使用应用程序中的查找功能开始骑行，并根据他们的位置，在地图视图中显示最近可用自行车的列表。用户可以选择任何可用的自行车，并使用应用程序内的导航辅助功能到达自行车。接下来，用户需要扫描自行车上的唯一快速响应（QR）码，然后简单点击解锁。

![图 13.1：用户可以扫描以解锁自行车的 QR 码](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_13_01.jpg)

图 13.1：用户可以扫描以解锁自行车的 QR 码

一旦自行车解锁，它就暂时与用户的账户关联起来。完成旅程后，用户需要将自行车停放在一个安全的地方，打开应用程序，点击锁定自行车，这将释放自行车与用户账户的关联。

### 实时跟踪

所有自行车都有内置的 GPS 跟踪设备，可以实时跟踪它们的位置。有了这种跟踪能力，用户可以轻松搜索周围地区的可用自行车，并使用导航辅助功能访问自行车。

此外，一旦骑行开始，每辆自行车的位置将每 30 秒记录一次并记录到系统中。这些记录将用于报告、分析和在紧急情况或盗窃时跟踪自行车。用户可以在任何时间将自行车带到城市的任何地方，实时跟踪帮助他们感到安全。

### 维护和保养

所有自行车都需要定期维护和仔细检查，以确保它们能够有效运行。这种维护每 15 天进行一次，期间自行车会被清洁，移动部件会被润滑，轮胎气压会被检查和调节，刹车会被检查和调整。每天，系统会识别需要维护的自行车，将它们从系统的可用自行车列表中移除，并通知一个技术团队。

# 技术讨论和决策

议案受到理事会成员的高度赞赏，他们对其尖端功能和低成本实施印象深刻，因为无桩系统比使用停靠式自行车要便宜得多。理事会准备采购自行车，修建自行车道，并在整个城市实施信号系统。他们还将准备使用和安全指南以及处理广告。初创团队负责构建 IT 基础设施和移动应用程序。

理事会坚持要求团队将 IT 基础设施成本降至最低，减少总体推出时间，并构建一个可扩展和灵活的系统以满足未来的需求变化。初创公司的技术团队进行了一些研究，以解决这些条件，详细内容如下。

### 快速推出

团队时间紧迫，需要找到一种*快速构建和快速交付*的方法。实现这一目标的关键是减少研究时间，并选择知名和经过验证的技术。技术团队已经准备好了移动应用程序和后端应用程序。他们现在唯一需要做的就是决定一个合适的数据库平台。需要一个数据库来持久化客户详细信息、自行车详细信息、自行车的实时位置和骑行详细信息。这个数据库平台应该快速设置，而不用太担心基础设施、集成、安全性或备份。团队决定选择**数据库即服务**（**DBaaS**）解决方案，以提供可靠、可扩展的解决方案，并缩短上市时间。

### 成本效益

由于理事会同时资助了许多项目，预算有点紧张。因此，他们决定先从 200 辆自行车开始，观察效果，并征求公众反馈。根据这些反馈，他们愿意将车队规模增加到 1,000 辆，甚至如果需要的话增加到 2,000 辆。车队规模的增加将进一步导致需要管理的数据量增加。为此，**DBaaS**平台是一个很好的选择，因为它允许您从最小的设置开始，并根据需要进行扩展。

最初的 200 辆自行车意味着最多会有 200 次骑行。因此，不需要进行大型数据集处理，因此团队决定选择低 RAM 和低 CPU 集群。随着车队规模的增长，他们可以进行横向或纵向扩展，并且成本始终会根据使用需求进行优化。

### 灵活

在一次理事会会议上，一些成员提出了以下建议：

+   收费：只有居民可以免费使用，而游客和访客将为每次骑行付费。

+   使用护照作为有效的身份证明：将护照添加到有效身份证件列表中。没有政府提供的照片身份证的客户可以使用他们的护照来注册系统。

+   将滑板车加入车队：系统应支持共享自行车和共享滑板车。

这些建议肯定会通过使系统更加用户友好来改进系统。然而，在这些建议纳入系统之前，需要进行一些分析。收费和支持不同类型的身份验证需要与联邦和外部系统集成。这种集成需要遵守相关部门发布的不同规则、法规和安全和隐私政策。

考虑到这些挑战，理事会决定坚持当前的第一阶段计划。建议更改的要求将在项目的第二阶段中得到最终确定并纳入。

技术团队了解到系统需要足够灵活，以便纳入任何尚不明确或不确定的未来更改。根据当前的技术设计，用户具有驾驶执照号码作为 ID，但需要更灵活地存储其他类型的 ID。此外，为了收取费用，模式需要足够灵活，以纳入用户的银行账户或信用卡详细信息。同样，为了引入车队中的滑板车（可能具有不同的维护要求或不同的费用结构），系统需要能够区分自行车和滑板车。

在这种情况下，传统的数据库实体，其受严格的模式定义约束，不是一个好选择。为了纳入一些未来的更改，它们的模式定义需要首先进行更新。使用传统数据库，模式更改很难推出和回滚。经过仔细考虑和比较，团队决定选择 MongoDB Atlas 集群。MongoDB 提供了灵活的模式和水平以及垂直扩展能力。Atlas 集群帮助推出一个生产级系统，只需点击几下即可，并且在成本和时间上节省了大量开支。在下一节中，我们将详细介绍数据库设计。

# 数据库设计

根据前几节描述的要求，要持久化的三个基本实体是`user`、`vehicle`和`ride`。`user`和`vehicle`实体将分别存储用户和车辆的属性，而`ride`实体将在开始新的骑行时创建。

除了基本实体外，还需要一个额外的实体来跟踪自行车骑行日志。对于每次活动骑行，系统会捕获并记录自行车的位置。这些日志将用于报告和分析目的。

由于 MongoDB 提供的基于文档的数据集，所有实体都可以轻松设计为集合。这些集合及其一些示例记录将在下一节中探讨。

## 用户

`users`集合保存了所有在系统中注册的用户的数据。以下代码片段显示了代表其中一个注册用户的示例文档：

```js
{
    "_id" : "a6e36e30-41fa-45bf-93c5-83da4efeed37",
    "email_address" : "ethel.112@example.com", 
    "first_name" : "Ethel",
    "last_name" : "Carter",
    "date_of_birth" : ISODate("1993-06-01T00:00:00Z"),
    "address" : {
        "street" : "51 Thornridge Cir",
        "city" : "Fair Bay",
        "state" : "North Roseland",
        "post_code" : 9924,
        "country" : "Roseland"
    },
    "registration_date" : ISODate("2020-11-24T00:00:00Z"),
    "id_documents" : [
    {
        "drivers_license" : {
            "license_number" : 2771556252,
            "issue_date" : ISODate("2011-04-18T00:00:00Z")
        }
    }],
    "payments" : [
    {
        "credit_card" : {
            "name_on_card" : "Ethel Carter",
            "card_number" : 342610644867494,
            "valid_till" : "3/22"
        }
    }]
}
```

文档中的主键是随机生成的唯一 UUID 字符串。还有其他字段用于保存用户的基本信息，如他们的名字、姓氏、出生日期、地址、电子邮件地址和系统注册日期。`id_documents`字段是一个数组，目前存储驾驶执照详细信息。将来，当启用其他 ID 类型，如护照时，用户将能够提供多个 ID 详细信息。目前收集付款详细信息是作为预防措施。除非自行车在骑行过程中损坏或被盗，否则客户不会被收费。`payments`字段是一个数组，目前存储信用卡详细信息。一旦系统与其他支付网关集成，用户将有其他支付方式的选择。

## 车辆

`vehicles`集合代表车队中的自行车。城市自行车最初将有 200 辆自行车。下面的车辆文档结构及所有字段和示例值将在以下片段中显示：

```js
{
    "_id" : "227fe7e0-76c7-410b-afe8-6ae5785ac937",
    "vehicle_type" : "bike|scooter",
    "status" : "available",
    "rollout_date" : ISODate("2020-10-20T00:00:00Z"),
    "make" : {
        "Manufacturer" : "Compass Cycles",
        "model_name" : "Unisex - Flatbar Carbon Frame Road Bike",
        "model_code" : "CBUFLATR101",
        "year" : 2020,
        "frame_number" : "FWJ166K23683958E"
    },
    "gears" : 3,
    "has_basket" : true,
    "has_helmet" : true,
    "bike_type" : "unisex|men|women",
    "location" : {
        "type" : "Point",
        "coordinates" : [
            111.189631,
            -72.454577
        ]
    },
    "last_maintenance_date" : ISODate("2020-11-05T00:00:00Z")
}
```

此文档中的主键是唯一的 UUID 字符串。此 ID 用于唯一地引用车辆，例如在 QR 码或车辆骑行详情中。还有其他静态字段用于表示车辆的投放日期、制造商名称、型号、车架号、齿轮数等。考虑到市政府未来计划推出滑板车，引入了一个名为 `vehicle_type` 的字段。该字段区分自行车和滑板车。`status` 字段表示自行车当前是否可用、正在骑行或正在维护（在这种情况下，它是可用的）。该字段可以包含这三个值中的任何一个：`available`、`on_ride` 和 `under_maintenance`。最后的维护日期有助于确定车辆是否需要维护。`location` 字段表示车辆的当前地理位置，并且在 MongoDB 的 `Point` 类型的地理空间索引中表示。其他可选字段，如 `has_basket`、`has_helmet` 和 `bike_type`，对于满足特定要求的客户非常有用。请注意，自行车型号可以分为 `男士`、`女士` 或中性自行车，而滑板车始终是中性的。因此，只有当 `vehicle_type` 为 `bike` 时，才会出现 `bike_type` 字段。

## 骑行

`rides` 集合代表了行程，该集合中的文档总数表示通过系统进行的骑行次数：

```js
{
    "_id" : "ebe89a65-ee02-4fa8-aba7-88c33751d487",
    "user_id" : "a6e36e30-41fa-45bf-93c5-83da4efeed37",
    "vehicle_id" : "227fe7e0-76c7-410b-afe8-6ae5785ac937",
    "start_time" : ISODate("2020-11-25T02:10:00Z"),
    "start_location" : {
        "type" : "Point",
        "coordinates" : [
            111.189631,
            -72.454577
        ]
    },
    "end_time" : ISODate("2020-11-25T03:17:00Z"),
    "end_location" : {
        "type" : "Point",
        "coordinates" : [
            111.045789,
            -72.456144
        ]
    },
    "feedback" : {
        "stars" : 5,
        "comment" : "Navigation helped me locate the bike quickly, enjoyed my           ride. Thank you City Bikes"
    }
}
```

每次骑行都有一个随机生成的 UUID 字符串作为主键。`user_id` 和 `vehicle_id` 字段分别表示当前使用骑行的用户和车辆。当用户解锁自行车时，将创建 `ride` 文档，并在创建时插入 `start_time` 和 `start_location` 字段。当用户在行程结束时锁定自行车时，将创建 `end_time` 和 `end_location` 字段。还有一个可选字段用于表示反馈，其中记录了星级评分和用户评论。

## 骑行日志

`ride_logs` 集合记录了每次活动骑行的进展，每隔 30 秒记录一次。该集合主要用于分析和报告。通过使用该集合中的数据，可以实时追踪任何骑行的完整路径。在骑行过程中，如果自行车发生事故或自行车丢失，自行车的最后记录的条目可以帮助定位它。以下代码片段显示了同一辆自行车骑行的三个连续日志条目：

```js
{
    "_id" : "6b868a75-5c47-4b36-a706-e84b486d4c40",
    "ride_id" : " -ee02-4fa8-aba7-88c33751d487",
    "time" : ISODate("2020-11-25T02:10:00Z"),
    "location":{
        "type":"Point",
        "coordinates":[111.189631, -72.454577]
    }
}
{
    "_id" : "e33f9d94-8787-4b0d-aa52-08795fab2b38",
    "ride_id" : "ebe89a65-ee02-4fa8-aba7-88c33751d487",
    "time" : ISODate("2020-11-25T02:10:30Z"),
    "location":{
        "type":"Point",
        "coordinates":[111.189425 -72.454582]
    }
}
{
    "_id" : "8d39567b-efc5-43d4-9034-f636c97c97b3",
    "ride_id" : "ebe89a65-ee02-4fa8-aba7-88c33751d487",
    "time" : ISODate("2020-11-25T02:11:00Z"),
    "location":{
        "type":"Point",
        "coordinates":[111.189291, -72.454585]
    }
}
```

每个日志条目都有一个唯一的 UUID 字符串作为主键。文档包含 `ride_id`，有助于追踪骑行、用户和车辆的详细信息。`time` 和 `location` 字段有助于跟踪车辆在特定时间的地理坐标。出于分析目的，可以以多种方式使用该集合生成有用的统计信息，以识别和解决现有问题或进行未来改进。例如，该集合有助于找出所有骑行的平均自行车速度、特定区域的平均速度，或特定年龄组骑手的平均速度。通过比较这些统计数据，市政府可以确定骑手倾向于在哪些城市区域骑行速度较慢，并提供充足的自行车道。此外，他们可以通过骑手年龄来检查自行车使用和速度模式，并指定安全速度限制。该集合还有助于找出城市中最受欢迎和最不受欢迎的自行车骑行区域。根据这些信息，市政府可以采取适当措施，在受欢迎的区域提供更多的自行车，在不受欢迎的区域提供更少的自行车。

本节介绍了 MongoDB 数据库结构的细节和集合的解剖结构。在下一节中，我们将通过一些示例场景来运行各种用例。

# 用例

前面的部分提供了 City Bikes 系统的概述，要求和考虑因素以及数据库结构。现在，我们将列出使用案例和数据库查询的系统使用情况，使用一些示例场景。这将有助于验证设计的正确性，并确保没有遗漏任何要求。

### 用户查找可用自行车

考虑这样一种情况，用户在其手机上打开应用程序，然后点击查找半径 300 米内的自行车。用户当前的坐标是*经度 111.189528 和纬度-72.454567*。下一个代码片段显示了相应的数据库查询：

```js
db.vehicles.find({
    "vehicle_type" : "bike", 
    "status" : "available",
    "location" : {
        $near : {
            $geometry : {
                "type" : "Point",
                "coordinates" : [111.189528, -72.454567]
            },
            $maxDistance : 300
        }
    }
})
```

查询所有当前可用并位于请求的 300 米半径内的自行车。

### 用户解锁自行车

用户扫描自行车上的 QR 码（`227fe7e0-76c7-410b-afe8-6ae5785ac937`），然后点击解锁。解锁自行车会开始骑行，并使自行车对其他用户不可用。

使用我们的数据库，此场景可以分为两个步骤实现。首先，应更改自行车的状态，然后应创建新的骑行记录。以下代码片段显示了如何执行此操作：

```js
db.vehicles.findOneAndUpdate(
    {"_id" : "227fe7e0-76c7-410b-afe8-6ae5785ac937"},
    {
        $set : {"status" : "on_ride"}
    }
)
```

上述命令将自行车的状态设置为`on_ride`。由于自行车的状态不再设置为`available`，因此其他用户执行的自行车搜索中将不会出现该自行车。下一个代码片段显示了`rides`集合上的`insert`命令：

```js
db.rides.insert({
    "_id" : "ebe89a65-ee02-4fa8-aba7-88c33751d487",
    "user_id" : "a6e36e30-41fa-45bf-93c5-83da4efeed37",
    "vehicle_id" : "227fe7e0-76c7-410b-afe8-6ae5785ac937",
    "start_time" : new Date("2020-11-25T02:10:00Z"),
    "start_location" : {
        "type" : "Point",
        "coordinates" : [
            111.189631,
            -72.454577
        ]
    }
})
```

此`insert`命令创建了一个新的骑行记录，并将用户、自行车和骑行关联在一起。它还捕获了骑行的开始时间和开始位置。

### 用户锁定自行车

骑行结束时，用户将自行车停放在安全位置，打开应用程序，然后点击屏幕完成骑行。这也需要两个步骤。首先，需要更新骑行记录的细节。其次，需要更新车辆的状态和新位置：

```js
db.rides.findOneAndUpdate(
    {"_id" : "ebe89a65-ee02-4fa8-aba7-88c33751d487"},
    {
        $set : {
            "end_time" : new Date("2020-11-25T03:17:00Z"),
            "end_location" : {
                "type" : "Point",
                "coordinates" : [
                    111.045789,
                    -72.456144
                ]
            }
        }
    }
)
```

上述命令设置了骑行的结束时间和坐标。请注意，缺少结束位置和结束时间表示骑行仍在进行中：

```js
db.vehicles.findOneAndUpdate(
    {"_id" : "227fe7e0-76c7-410b-afe8-6ae5785ac937"},
    {
        $set : {
            "status" : "available",
            "location" : {
                "type" : "Point",
                "coordinates" : [
                    111.045789,
                    -72.456144
                ]
            }
        }
    }
)
```

上述命令将车辆标记为可用，并使用新坐标更新其位置。

### 系统记录骑行的地理坐标

每 30 秒，一个预定的作业查询所有活动骑行的自行车，通过 GPS 收集它们的最新地理坐标，并为每辆自行车创建骑行记录条目。下一个代码片段显示了`logs`集合的`insert`命令：

```js
db.ride_logs.insert({
    "_id" : "8d39567b-efc5-43d4-9034-f636c97c97b3",
    "ride_id" : "ebe89a65-ee02-4fa8-aba7-88c33751d487",
    "time" : new Date(),
    "location":{
        "type":"Point",
        "coordinates":[
            111.189291, 
            -72.454585
        ]
   }
})
```

上述命令演示了如何创建新的骑行记录。它使用`new Date()`在*GMT*中记录当前时间戳，并插入给定自行车骑行的最新位置坐标。

### 系统将自行车送去维护

所有自行车每两周需要定期维护。技术人员定期检查自行车并修复任何已识别的问题。每天午夜都会执行一个预定的作业，并检查所有自行车的最后维护日期。该作业有助于找到所有自行车，其维护在过去 15 天内未完成，并将其标记为需要维护。然后自行车变为不可用。以下命令查找所有最后维护日期早于当前日期 15 天的自行车：

```js
db.vehicles.updateMany(
    {
        "last_maintenance_date" : {
            $lte : new Date(new Date() - 1000 * 60 * 60 * 24 * 15)
        }
    },
    {
        $set : {"status" : "under_maintenance"}
    }
)
```

`1000 * 60 * 60 * 24 * 15`表达式表示 15 天的毫秒数。然后从当前日期中减去计算出的毫秒数，以找到 15 天前的日期。如果自行车的`last_maintenance_date`字段早于 15 天，其状态将标记为`under_maintenance`。

### 技术人员每两周进行一次维护

技术团队找到所有状态为`under_maintenance`的自行车，进行维护，并使自行车可用：

```js
db.vehicles.findOneAndUpdate(
    {"_id" : "227fe7e0-76c7-410b-afe8-6ae5785ac937"},
    {
        $set : {
            "status" : "available",
            "last_maintenance_date" : new Date()
        }
    }
)
```

此命令将自行车状态设置为可用，并将`last_maintenance_date`设置为当前时间戳。

### 生成统计数据

分析师的任务是利用应用程序生成的各种统计数据，识别改进和优化的领域，以及评估系统在资金支出方面的好处。他们可以以多种方式使用数据库；然而，我们将使用一个示例用例进行演示。

城市的中央公园（位于*108.146337，-78.617716*）是一个非常受欢迎和拥挤的地方。为了方便骑车者骑行，议会在公园周围建造了特殊的自行车道。议会想知道有多少 City Bike 骑手在这些车道上骑行。

分析师执行了一个快速查询，以找到在中央公园 200 米半径范围内骑行的自行车行程：

```js
db.ride_logs.distinct(
    "ride_id", 
    {
        "location" : {
            $near : {
                $geometry : {
                    "type" : "Point",
                    "coordinates" : [108.146337, -78.617716]
                },
                $maxDistance : 200
            }
        }
    }
)
```

这个特殊的查询在`ride_logs`上过滤所有日志条目，以找出有多少自行车骑行与给定位置地理上接近，并打印它们的骑行 ID。

在本节中，我们讨论了应用程序可以使用的各种场景，并使用 MongoDB 查询和命令满足了它们。

# 摘要

本章探讨了一个虚构城市议会实施的 City Bikes 项目。首先考虑了议会可能面临的问题，以及项目提案如何解决这些问题。这些考虑包括议会的时间和预算、不确定的需求，以及技术团队决定使用基于 MongoDB Atlas 的 Database-as-a-Service（DBaaS）解决方案来解决所有这些问题。您详细研究了数据库设计，并审查了 MongoDB 查询，以记录、实施和解决本示例系统中的几个示例场景。

在整个课程中，您通过实际示例和应用程序介绍了 MongoDB 的各种功能和优势。您从 MongoDB 的基础知识开始，了解了它的性质和功能，以及它与传统的 RDBMS 数据库的区别。然后，您揭示了其基于 JSON 的数据结构和灵活的模式所提供的优势。接下来，您学习了核心数据库操作和运算符，以从集合中查找、聚合、插入、更新和删除数据，以及更高级的概念，如性能改进、复制、备份和恢复，以及数据可视化。您还在云中使用 MongoDB Atlas 创建了自己的 MongoDB 数据库集群，然后将真实的示例数据集加载到了集群中，并在整本书中使用了这些数据。最后，本章通过演示 MongoDB 解决方案如何解决现实生活中的问题来结束了本课程。

通过本书学到的知识和技能，您将能够在工作场所或自己的个人项目中实施高度可扩展、强大的数据库设计，以满足业务需求。
