# Hibernate 搜索示例（二）

> 原文：[`zh.annas-archive.org/md5/5084F1CE5E9C94A43DE0A69E72C391F6`](https://zh.annas-archive.org/md5/5084F1CE5E9C94A43DE0A69E72C391F6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：高级查询

在本章中，我们将详细阐述我们在前面章节中介绍的基本搜索查询概念，并融入我们刚刚学到的新的映射知识。现在，我们将探讨使搜索查询更具灵活性和强大性的多种技术。

我们将看到如何在数据库甚至还没有被触碰的情况下，在 Lucene 层面动态地过滤结果。我们还将通过使用基于投影的查询，避免数据库调用，直接从 Lucene 检索属性。我们将使用面向面的搜索，以识别和隔离搜索结果中的数据子集。最后，我们将介绍一些杂项查询工具，如查询时的提升和为查询设置时间限制。

# 过滤

构建查询的过程围绕着寻找匹配项。然而，有时你希望根据一个明确没有匹配的准则来缩小搜索结果。例如，假设我们想要限制我们的 VAPORware Marketplace 搜索，只支持特定设备上的那些应用：

+   向现有查询添加关键词或短语是没有帮助的，因为这只会使查询更加包容。

+   我们可以将现有的查询转换为一个布尔查询，增加一个额外的`must`子句，但这样 DSL 开始变得难以维护。此外，如果你需要使用复杂的逻辑来缩小你的结果集，那么 DSL 可能提供不了足够的灵活性。

+   一个 Hibernate Search 的`FullTextQuery`对象继承自 Hibernate ORM 的`Query`（或其 JPA 对应物）类。因此，我们可以使用像`ResultTransformer`这样的核心 Hibernate 工具来缩小结果集。然而，这需要进行额外的数据库调用，这可能会影响性能。

Hibernate Search 提供了一种更优雅和高效的**过滤器**方法。通过这种机制，各种场景的过滤逻辑被封装在单独的类中。这些过滤器类可以在运行时动态地启用或禁用，也可以以任何组合方式使用。当查询被过滤时，不需要从 Lucene 获取不想要的结果。这减少了后续数据库访问的负担。

## 创建一个过滤器工厂

为了通过支持设备来过滤我们的搜索结果，第一步是创建一个存储过滤逻辑的类。这应该是`org.apache.lucene.search.Filter`的实例。对于简单的硬编码逻辑，你可能只需创建你自己的子类。

然而，如果我们通过过滤器工厂动态地生成过滤器，那么我们就可以接受参数（例如，设备名称）并在运行时定制过滤器：

```java
public class DeviceFilterFactory {

   private String deviceName;

 @Factory
   public Filter getFilter() {
      PhraseQuery query = new PhraseQuery();
      StringTokenizertokenzier = new StringTokenizer(deviceName);
      while(tokenzier.hasMoreTokens()) {
         Term term = new Term(
            "supportedDevices.name", tokenzier.nextToken());
         query.add(term);
      }
 Filter filter = new QueryWrapperFilter(query);
      return new CachingWrapperFilter(filter);
   }

   public void setDeviceName(String deviceName) {
      this.deviceName = deviceName.toLowerCase();
   }

}
```

`@Factory`注解应用于负责生成 Lucene 过滤器对象的方法。在这个例子中，我们注解了恰当地命名为`getFilter`的方法。

### 注意

不幸的是，构建 Lucene `Filter`对象要求我们更紧密地与原始 Lucene API 合作，而不是 Hibernate Search 提供的方便的 DSL 包装器。Lucene 完整 API 非常复杂，要完全覆盖它需要一本完全不同的书。然而，即使这种浅尝辄止也足够深入地为我们提供编写真正有用过滤器的工具。

这个例子通过包装一个 Lucene 查询来构建过滤器，然后应用第二个包装器以促进过滤器缓存。使用特定类型的查询是`org.apache.lucene.search.PhraseQuery`，它相当于我们在第三章，*执行查询*中探讨的 DSL 短语查询。

### 提示

我们在这个例子中研究短语查询，因为它是一种非常有用的过滤器构建类型。然而，总共有 15 种 Lucene 查询类型。你可以探索[`lucene.apache.org/core/old_versioned_docs/versions/3_0_3/api/all/org/apache/lucene/search/Query.html`](http://lucene.apache.org/core/old_versioned_docs/versions/3_0_3/api/all/org/apache/lucene/search/Query.html)上的 JavaDocs。

让我们回顾一下关于数据在 Lucene 索引中是如何存储的一些知识。默认情况下，分析器对字符串进行分词，并将它们作为单独的词项进行索引。默认分析器还将字符串数据转换为小写。Hibernate Search DSL 通常隐藏所有这些细节，因此开发人员不必考虑它们。

然而，当你直接使用 Lucene API 时，确实需要考虑这些事情。因此，我们的`setDeviceName`设置器方法手动将`deviceName`属性转换为小写，以避免与 Lucene 不匹配。`getFilter`方法随后手动将此属性拆分为单独的词项，同样是为了与 Lucene 索引的匹配。

每个分词词项都用于构造一个 Lucene `Term`对象，该对象包含数据和相关字段名（即在这个案例中的`supportedDevices.name`）。这些词项一个接一个地添加到`PhraseQuery`对象中，按照它们在短语中出现的确切顺序。然后将查询对象包装成过滤器并返回。

### 添加过滤器键

默认情况下，Hibernate Search 为更好的性能缓存过滤器实例。因此，每个实例需要引用缓存中的唯一键。在这个例子中，最逻辑的键将是每个实例过滤的设备名称。

首先，我们在过滤器工厂中添加一个新方法，用`@Key`注解表示它负责生成唯一键。这个方法返回`FilterKey`的一个子类：

```java
...
@Key
Public FilterKey getKey() {
   DeviceFilterKey key = new DeviceFilterKey();
   key.setDeviceName(this.deviceName);
   return key;
}
...
```

自定义`FilterKey`子类必须实现`equals`和`hashCode`方法。通常，当实际包装的数据可以表示为字符串时，你可以委派给`String`类相应的`equals`和`hashCode`方法：

```java
public class DeviceFilterKey extends FilterKey {

   private String deviceName;

 @Override
 public boolean equals(Object otherKey) {
      if(this.deviceName == null
           || !(otherKey instanceof DeviceFilterKey)) {
         return false;
      }
      DeviceFilterKeyotherDeviceFilterKey =
           (DeviceFilterKey) otherKey;
      return otherDeviceFilterKey.deviceName != null
              && this.deviceName.equals(otherDeviceFilterKey.deviceName);
   }

 @Override
 public int hashCode() {
      if(this.deviceName == null) {
         return 0;
      }
      return this.deviceName.hashCode();
   }

   // GETTER AND SETTER FOR deviceName...
}
```

## 建立过滤器定义

为了使这个过滤器对我们应用的搜索可用，我们将在`App`实体类中创建一个过滤器定义：

```java
...
@FullTextFilterDefs({
   @FullTextFilterDef(
      name="deviceName", impl=DeviceFilterFactory.class
   )
})
public class App {
...
```

`@FullTextFilterDef`注解将实体类与给定的过滤器或过滤器工厂类关联，由`impl`元素指定。`name`元素是一个字符串，Hibernate Search 查询可以用它来引用过滤器，正如我们在下一小节中看到的。

一个`entity`类可以有任意数量的定义过滤器。复数形式的`@FullTextFilterDefs`注解支持这一点，通过包裹一个由逗号分隔的一个或多个单数形式的`@FullTextFilterDef`注解列表。

## 为查询启用过滤器

最后但并非最不重要的是，我们使用`FullTextQuery`对象的`enableFullTextFilter`方法为 Hibernate Search 查询启用过滤器定义：

```java
...
if(selectedDevice != null && !selectedDevice.equals("all")) {
   hibernateQuery.enableFullTextFilter("deviceName")
      .setParameter("deviceName", selectedDevice);
}
...
```

这个方法的`string`参数与查询中涉及的实体类之一的过滤器定义相匹配。在这个例子中，是`App`上定义的`deviceName`过滤器。当 Hibernate Search 找到这个匹配项时，它会自动调用相应的过滤器工厂来获取一个`Filter`对象。

我们的过滤器工厂使用一个参数，也称为`deviceName`以保持一致性（尽管它是一个不同的变量）。在 Hibernate Search 可以调用工厂方法之前，这个参数必须被设置，通过将参数名和值传递给`setParameter`。

过滤器是在`if`块中启用的，这样在没有选择设备时（也就是，*所有设备*选项），我们可以跳过这一步。如果你检查本章版本 VAPORware Marketplace 应用的可下载代码包，你会看到 HTML 文件已经被修改为添加了设备选择的下拉菜单：

![为查询启用过滤器](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205_05_01.jpg)

# 投影

在前几章中，我们的示例应用程序在一次大的数据库调用中获取所有匹配的实体。我们在第三章，*执行查询*中引入了分页，以至少限制数据库调用到的行数。然而，由于我们最初已经在 Lucene 索引中搜索数据，真的有必要去数据库吗？

休眠搜索提供了**投影**作为一种减少或至少消除数据库访问的技术。基于投影的搜索只返回从 Lucene 中提取的特定字段，而不是从数据库中返回完整的实体对象。然后你可以去数据库获取完整的对象（如果需要），但 Lucene 中可用的字段本身可能就足够了。

本章的 VAPORware Marketplace 应用程序版本的搜索结果页面修改为现在使用基于查询的投影。之前的版本页面一次性收到`App`实体，并在点击每个应用的**完整详情**按钮之前隐藏每个应用的弹出窗口。现在，页面只接收足够构建摘要视图的字段。每个**完整详情**按钮触发对该应用的 AJAX 调用。只有在那时才调用数据库，并且仅为了获取那一个应用的数据。

### 注意

从 JavaScript 中进行 AJAX 调用以及编写响应这些调用的 RESTful 网络服务的详尽描述，已经超出了本 Hibernate Search 书籍的范围。

说到这里，所有的 JavaScript 都包含在搜索结果的 JSP 中，在`showAppDetails`函数内。所有相应的服务器端 Java 代码都位于`com.packtpub.hibernatesearch.rest`包中，并且非常注释。网络上 endless online primers and tutorials for writing RESTful services, and the documentation for the particular framework used here is at [`jersey.java.net/nonav/documentation/latest`](http://jersey.java.net/nonav/documentation/latest).

## 创建一个基于查询的查询投影

要将`FullTextQuery`更改为基于投影的查询，请对该对象调用`setProjection`方法。现在我们的搜索 servlet 类包含以下内容：

```java
...
hibernateQuery.setProjection("id", "name", "description", "image");
...
```

该方法接受一个或多个字段名称，从与该查询关联的 Lucene 索引中提取这些字段。

## 将投影结果转换为对象形式

如果我们到此为止，那么查询对象的`list()`方法将不再返回`App`对象的列表！默认情况下，基于投影的查询返回对象数组列表（即`Object[]`）而不是实体对象。这些数组通常被称为**元组**。

每个元组中的元素包含投影字段的值，按它们声明的顺序排列。例如，这里`listItem[0]`将包含结果的 ID 值，`field.listItem[1]`将包含名称，`value.listItem[2]`将包含描述，依此类推。

在某些情况下，直接使用元组是很简单的。然而，您可以通过将 Hibernate ORM 结果转换器附加到查询来自动将元组转换为对象形式。这样做再次改变了查询的返回类型，从`List<Object[]>`变为所需对象类型的列表：

```java
...
hibernateQuery.setResultTransformer(
   newAliasToBeanResultTransformer(App.class) );
...
```

您可以创建自己的自定义转换器类，继承自`ResultTransformer`，实现您需要的任何复杂逻辑。然而，在大多数情况下，Hibernate ORM 提供的开箱即用的子类已经足够了。

这里，我们使用`AliasToBeanResultTransformer`子类，并用我们的`App`实体类对其进行初始化。这将与投影字段匹配，并将每个属性的值设置为相应的字段值。

只有`App`的一部分属性是可用的。保留其他属性未初始化是可以的，因为搜索结果的 JSP 在构建其摘要列表时不需要它们。另外，生成的`App`对象实际上不会附加到 Hibernate 会话。然而，我们在此之前已经将我们的结果分离，然后再发送给 JSP。

## 使 Lucene 字段可用于投影

默认情况下，Lucene 索引是为假设它们不会用于基于投影的查询而优化的。因此，投影需要你做一些小的映射更改，并记住几个注意事项。

首先，字段数据必须以可以轻松检索的方式存储在 Lucene 中。正常的索引过程优化数据以支持复杂查询，而不是以原始形式检索。为了以可以被投影恢复的形式存储字段的值，你需要在`@Field`注解中添加一个`store`元素：

```java
...
@Field(store=Store.COMPRESS)
private String description;
...
```

这个元素取三个可能值的枚举：

+   `Store.NO`是默认值。它使字段被索引用于搜索，但不能通过投影以原始形式检索。

+   `Store.YES`使字段以原样包含在 Lucene 索引中。这增加了索引的大小，但使投影变得可能。

+   `Store.COMPRESS`是对妥协的尝试。它也将字段存储原样，但应用压缩以减少整体索引大小。请注意，这更占用处理器资源，并且不适用于同时使用`@NumericField`注解的字段。

其次，一个字段必须使用双向字段桥。Hibernate Search 中所有内置的默认桥都支持这一点。然而，如果你创建自己的自定义桥类型（请参阅第四章，*高级映射*），它必须基于`TwoWayStringBridge`或`TwoWayFieldBridge`。

最后但并非最不重要的是，投影仅适用于实体类本身的基属性。它不是用来获取关联实体或内嵌对象的。如果你尝试引用一个关联，那么你只能得到一个实例，而不是你可能期望的完整集合。

### 提示

如果你需要与关联或内嵌对象一起工作，那么你可能需要采用我们示例应用程序所使用的方法。Lucene 投影检索所有搜索结果的基本属性，包括实体对象的的主键。当我们后来需要与实体对象的关联一起工作时，我们通过数据库调用使用那个主键只检索必要的行。

# 分面搜索

Lucene 过滤器是缩小查询范围到特定子集的强大工具。然而，过滤器对预定义的子集起作用。你必须已经知道你在寻找什么。

有时你需要动态地识别子集。例如，让我们给我们的`App`实体一个表示其类别的`category`属性：

```java
...
@Column
@Field
private String category;
...
```

当我们为应用执行关键字搜索时，我们可能想知道哪些类别在结果中有所体现以及每个类别下有多少结果。我们还可能想知道发现了哪些价格范围。所有这些信息都有助于用户更有效地缩小查询。

## 离散切片

动态识别维度然后通过它们进行过滤的过程称为**切片搜索**。Hibernate Search 查询 DSL 有一个流程为此，从 `QueryBuilder` 对象的 `facet` 方法开始：

![离散切片](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205_05_02.jpg)

离散切片请求流程（虚线灰色箭头表示可选路径）

`name` 方法需要一个描述性标识符作为此切片的名称（例如，`categoryFacet`），以便后来可以通过查询引用它。熟悉的 `onField` 子句声明了按结果分组的字段（例如，`category`）。

`discrete` 子句表示我们是按单个值分组，而不是按值的范围分组。我们将在下一节探讨范围切片。

`createFacetingRequest` 方法完成此过程并返回一个 `FacetingRequest` 对象。然而，还有三个可选的方法，你可以先调用它们中的任何一个，可以任意组合：

+   `includeZeroCounts`：它导致 Hibernate Search 返回所有可能的切片，甚至在当前搜索结果中没有任何点击的那些。默认情况下，没有点击的切片会被悄悄忽略。

+   `maxFacetCount`：它限制返回的切片数量。

+   `orderedBy`：它指定了找到的切片的排序顺序。与离散切片相关的三个选项是：

    +   `COUNT_ASC`: 按相关搜索结果的数量升序排列切片。数量最少点击的切片将被首先列出。

    +   `COUNT_DESC`：这与 `COUNT_ASC` 正好相反。切片从点击量最高到最低依次列出。

    +   `FIELD_VALUE`：按相关字段的值字母顺序排序切片。例如，"business" 类别会在 "games" 类别之前。

本章版本的 VAPORware Marketplace 现在包括以下设置 `app` 类别切片搜索的代码：

```java
...
// Create a faceting request
FacetingRequestcategoryFacetingRequest =
 queryBuilder
 .facet()
   .name("categoryFacet")
   .onField("category")
   .discrete()
   .orderedBy(FacetSortOrder.FIELD_VALUE)
   .includeZeroCounts(false)
   .createFacetingRequest();

// Enable it for the FullTextQuery object
hibernateQuery.getFacetManager().enableFaceting(
   categoryFacetingRequest);
...
```

现在切片请求已启用，我们可以运行搜索查询并使用我们刚刚声明的 `categoryFacet` 名称检索切片信息：

```java
...
List<App> apps = hibernateQuery.list();

List<Facet> categoryFacets =
   hibernateQuery.getFacetManager().getFacets("categoryFacet");
...
```

`Facet` 类包括一个 `getValue` 方法，该方法返回特定组的字段值。例如，如果一些匹配的应用程序属于 "business" 类别，那么其中一个切片将具有字符串 "business" 作为其值。`getCount` 方法报告与该切片关联多少搜索结果。

使用这两个方法，我们的搜索 servlet 可以遍历所有类别切片，并构建一个集合，用于在搜索结果 JSP 中显示：

```java
...
Map<String, Integer> categories = new TreeMap<String, Integer>();
for(Facet categoryFacet : categoryFacets) {

   // Build a collection of categories, and the hit count for each
   categories.put(
 categoryFacet.getValue(),categoryFacet.getCount());

   // If this one is the *selected* category, then re-run the query
   // with this facet to narrow the results
   if(categoryFacet.getValue().equalsIgnoreCase(selectedCategory)) {
      hibernateQuery.getFacetManager()
 .getFacetGroup("categoryFacet").selectFacets(categoryFacet);
       apps = hibernateQuery.list();
   }
}
...
```

如果搜索 servlet 接收到带有`selectedCategory` CGI 参数的请求，那么用户选择将结果缩小到特定类别。所以如果这个字符串与正在迭代的面元值匹配，那么该面元就为`FullTextQuery`对象“选中”。然后可以重新运行查询，它将只返回属于该类别的应用程序。

## 范围面元

面元不仅仅限于单一的离散值。一个面元也可以由一个值范围创建。例如，我们可能想根据价格范围对应用程序进行分组——搜索结果中的价格低于一美元、在一到五美元之间，或者高于五美元。

Hibernate Search DSL 的范围面元需要将离散面元流程的元素与我们在第三章 *执行查询* 中看到的范围查询的元素结合起来：

![范围面元](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205_05_03.jpg)

范围面元请求流程（虚线灰色箭头代表可选路径）

您可以定义一个范围为大于、小于或介于两个值之间（即`from` – `to`）。这些选项可以组合使用以定义尽可能多的范围子集。

与常规范围查询一样，可选的`excludeLimit`方法将其边界值从范围内排除。换句话说，`above(5)`意味着“大于或等于 5”，而`above(5).excludeLimit()`意味着“大于 5，*期终*”。

可选的`includeZeroCounts`、`maxFacetCount`和`orderBy`方法与离散面元的方式相同。然而，范围面元提供了一个额外的排序顺序选择。`FacetSortOrder.RANGE_DEFINITION_ODER`使得面元按照它们被定义的顺序返回（注意“`oder`”中缺少了“`r`”）。

在针对`category`的离散面元请求中，本章的示例代码还包括以下代码段以启用`price`的范围面元：

```java
...
FacetingRequestpriceRangeFacetingRequest =
 queryBuilder
 .facet()
      .name("priceRangeFacet")
      .onField("price")
      .range()
      .below(1f).excludeLimit()
      .from(1f).to(5f)
      .above(5f).excludeLimit()
      .createFacetingRequest();
hibernateQuery.getFacetManager().enableFaceting(
   priceRangeFacetingRequest);
...
```

如果你查看`search.jsp`的源代码，现在包括了在每次搜索中找到的类别和价格范围面元。这两种面元类型可以组合使用以缩小搜索结果，当前选中的面元以粗体突出显示。当**所有**选中任一类型时，该特定面元被移除，搜索结果再次扩大。

![范围面元](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205_05_04.jpg)

# 查询时的提升

在第三章 *执行查询* 中，我们看到了如何在索引时间固定或动态地提升字段的的相关性。在查询时间动态改变权重也是可能的。

Hibernate Search DSL 中的所有查询类型都包括`onField`和`andField`方法。对于每个查询类型，这两个子句也支持一个`boostedTo`方法，它接受一个`weight`因子作为`float`参数。无论该字段索引时的权重可能是什么，添加一个`boostedTo`子句就会将它乘以指示的数字：

```java
...
luceneQuery = queryBuilder
      .phrase()
      .onField("name").boostedTo(2)
      .andField("description").boostedTo(2)
      .andField("supportedDevices.name")
      .andField("customerReviews.comments")
      .sentence(unquotedSearchString)
      .createQuery();
...
```

在本章的 VAPORware Marketplace 应用程序版本中，查询时的提升现在添加到了“确切短语”用例中。当用户用双引号括起他们的搜索字符串以通过短语而不是关键词进行搜索时，我们想要给`App`实体的名称和描述字段比正常情况下更多的权重。高亮显示的更改将这两个字段在索引时的权重加倍，但只针对确切短语查询，而不是所有查询类型。

# 设置查询的超时

我们一直在工作的这个示例应用程序有一个有限的测试数据集，只有十几款应用程序和几款设备。因此，只要你的计算机有合理的处理器和内存资源，搜索查询应该几乎立即运行。

然而，一个带有真实数据的应用程序可能涉及跨数百万个实体的搜索，你的查询可能存在运行时间过长的风险。从用户体验的角度来看，如果你不限制查询的执行时间，可能会导致应用程序响应缓慢。

Hibernate Search 提供了两种时间盒查询的方法。一种是通过`FullTextQuery`对象的`limitExecutionTime`方法：

```java
...
hibernateQuery.limitExecutionTimeTo(2, TimeUnit.SECONDS);
...
```

这个方法会在指定的时间后优雅地停止查询，并返回它找到的所有结果直到那个点。第一个参数是时间单位数，第二个参数是时间单位类型（例如，微秒、毫秒、秒等）。前面的代码片段将尝试在搜索两秒后停止查询。

### 提示

查询运行后，你可以通过调用对象的`hasPartialResults()`方法来确定是否被中断。这个布尔方法如果在查询在自然结束之前超时就返回`true`。

第二种方法，使用`setTimeout()`函数，在概念上和接受的参数上与第一种相似：

```java
...
hibernateQuery.setTimeout(2, TimeUnit.SECONDS);
...
```

然而，这个方法适用于搜索在超时后应该完全失败，而不是像没发生过一样继续进行的情况。在前面的查询对象在运行两秒后会抛出`QueryTimeoutException`异常，并且不会返回在这段时间内找到的任何结果。

### 注意

请注意，这两种方法中，Hibernate Search 都会尽其所能尊重指定的一段时间。实际上，查询停止可能会需要一点额外的时间。

另外，这些超时设置只影响 Lucene 访问。一旦你的查询完成了对 Lucene 的搜索并开始从数据库中提取实际实体，超时控制就由 Hibernate ORM 而不是 Hibernate Search 来处理。

# 摘要

在本书的这一章，我们探讨了更多高级的技术来缩小搜索结果，提高匹配的相关性，以及提高性能。

现在我们可以使用 Lucene 过滤器来缩小匹配结果的一个固定子集。我们也看到了如何使用面向面的搜索在结果中动态识别子集。通过基于投影的查询，我们可以减少甚至消除实际数据库调用的需要。现在我们知道如何在查询时而非仅在索引时调整字段的相关性。最后但同样重要的是，我们现在能够为我们的查询设置时间限制，并优雅地处理搜索运行时间过长的情形。

在下一章中，我们将转向管理和维护的内容，学习如何配置 Hibernate Search 和 Lucene 以实现最佳性能。


# 第六章 系统配置和索引管理

在本章中，我们将查看 Lucene 索引的配置选项，并学习如何执行基本维护任务。我们将了解如何切换 Lucene 索引的自动和手动更新。我们将研究低延迟写操作、同步与异步更新以及其他性能优化选择。

我们将介绍如何为更好的性能对 Lucene 索引进行碎片整理和清理，以及如何完全不用接触硬盘存储来使用 Lucene。最后但并非最不重要的是，我们将接触到**Luke**这个强大的工具，用于在应用程序代码之外操作 Lucene 索引。

# 自动与手动索引

到目前为止，我们实际上并没有太多考虑实体索引的时间。毕竟，Hibernate Search 与 Hibernate ORM 紧密集成。默认情况下，附加组件在核心更新数据库时更新 Lucene。

然而，你有选择将这些操作解耦的选项，如果你愿意，可以手动索引。一些你可能考虑手动方法的常见情况如下：

+   如果你能轻松地忍受在有限的时间内 Lucene 与数据库不同步，你可能想将索引操作推迟到非高峰时段，以在系统高峰使用期间减轻负载。

+   如果你想使用条件索引，但又不习惯`EntityIndexingInterceptor`的实验性质（参见第四章，*高级映射*），你可以使用手动索引作为一种替代方法。

+   如果你的数据库可能直接被不通过 Hibernate ORM 的过程更新，你必须定期手动更新 Lucene 索引，以保持它们与数据库同步。

要禁用自动索引，请在`hibernate.cfg.xml`（或使用 JPA 时的`persistence.xml`）中设置`hibernate.search.indexing_strategy`属性为`manual`，如下所示：

```java
...
<property name="hibernate.search.indexing_strategy">manual</property>
...
```

## 单独更新

当自动索引被禁用时，手动索引操作是由`FullTextSession`对象上的方法驱动的（无论是传统的 Hibernate 版本还是 JPA 版本）。

### 添加和更新

这些方法中最重要的是`index`，它同时处理数据库侧的**添加**和**更新**操作。此方法接受一个参数，是任何为 Hibernate Search 索引配置的实体类的实例。

本章的 VAPORware Marketplace 应用程序使用手动索引。`StartupDataLoader`在将 app 持久化到数据库后立即调用每个 app 的`index`：

```java
...
fullTextSession.save(theCloud);
fullTextSession.index(theCloud);
...
```

在 Lucene 侧，`index`方法在与数据库侧`save`方法相同的交易上下文中工作。只有在事务提交时才进行索引。在回滚事件中，Lucene 索引不受影响。

### 注意

手动使用`index`会覆盖任何条件索引规则。换句话说，`index`方法忽略与该实体类注册的任何`EntityIndexingInterceptor`。

对于批量更新（请参阅*批量更新*部分），情况并非如此，但在考虑对单个对象进行手动索引时，这是需要记住的。调用`index`的代码需要先检查任何条件。

### 删除

从 Lucene 索引中删除实体的基本方法是`purge`。这个方法与`index`有点不同，因为你不需要向它传递一个要删除的对象实例。相反，你需要传递实体类引用和一个特定实例的 ID（即对应于`@Id`或`@DocumentId`）：

```java
...
fullTextSession.purge(App.class, theCloud.getId());
fullTextSession.delete(theCloud);
...
```

Hibernate Search 还提供了`purgeAll`，这是一个方便的方法，用于删除特定实体类型的所有实例。这个方法也需要实体类引用，尽管显然不需要传递特定的 ID：

```java
...
fullTextSession.purgeAll(App.class);
...
```

与`index`一样，`purge`和`purgeAll`都在事务内操作。**删除**实际上直到事务提交才会发生。如果在回滚的情况下，什么也不会发生。

如果你想在事务提交之前真正地向 Lucene 索引中写入数据，那么无参数的`flushToIndexes`方法允许你这样做。如果你正在处理大量实体，并且想要在过程中释放内存（使用`clear`方法）以避免`OutOfMemoryException`，这可能很有用：

```java
...
fullTextSession.index(theCloud);
fullTextSession.flushToIndexes();
fullTextSession.clear();
...
```

## 批量更新

单独添加、更新和删除实体可能会相当繁琐，而且如果你错过了某些东西，可能会出现错误。另一个选择是使用`MassIndexer`，它可以被认为是自动索引和手动索引之间的某种折中方案。

这个工具类仍然需要手动实例化和使用。然而，当它被调用时，它会一次性重建所有映射实体类的 Lucene 索引。不需要区分添加、更新和删除，因为该操作会抹掉整个索引，并从头开始重新创建它。

`MassIndexer`是通过`FullTextSession`对象的`createIndexer`方法实例化的。一旦你有一个实例，启动批量索引有两种方式：

+   `start`方法以异步方式索引，这意味着索引在后台线程中进行，而主线程的代码流程继续。

+   `startAndWait`方法以同步模式运行索引，这意味着主线程的执行将一直阻塞，直到索引完成。

当以同步模式运行时，你需要用 try-catch 块包装操作，以防主线程在等待时被中断：

```java
...
try {
 fullTextSession.createIndexer().startAndWait();
} catch (InterruptedException e) {
   logger.error("Interrupted while wating on MassIndexer: "
      + e.getClass().getName() + ", " + e.getMessage());
}
...
```

### 提示

如果实际可行，当应用程序离线且不响应查询时，使用批量索引会更好。索引会将系统负载加重，而且 Lucene 与数据库相比会处于一个非常不一致的状态。

大规模索引与个别更新在两个方面有所不同：

+   `MassIndexer`操作不是事务性的。没有必要将操作包装在 Hibernate 事务中，同样，如果出现错误，你也不能依赖回滚。

+   `MassIndexer`确实支持条件索引（参考第四章，*高级映射*）。如果你为那个实体类注册了一个`EntityIndexingInterceptor`，它将被调用以确定是否实际索引特定实例。

    ### 注意

    `MassIndexer`对条件索引的支持是在 Hibernate Search 的 4.2 代中添加的。如果你正在使用一个较老版本的应用程序，你需要将应用程序迁移到 4.2 或更高版本，以便同时使用`EntityIndexingInterceptor`和`MassIndexer`。

# 索引碎片化

随着时间的推移，对 Lucene 索引的更改会逐渐使其变得效率更低，就像硬盘可能会变得碎片化一样。当新的实体被索引时，它们会被放入一个与主索引文件分离的文件（称为**片段**）。当一个实体被删除时，它实际上仍然留在索引文件中，只是被标记为不可访问。

这些技术有助于使 Lucene 的索引尽可能适用于查询，但随着时间的推移，这会导致性能变慢。打开多个片段文件是慢的，并且可能会遇到操作系统对打开文件数量的限制。保留在索引中的已删除实体会使文件比必要的更膨胀。

将所有这些片段合并在一起，并真正清除已删除实体的过程称为**优化**。这个过程类似于对硬盘进行碎片整理。Hibernate Search 提供了基于手动或自动的基础上的索引优化机制。

## 手动优化

`SearchFactory`类提供了两种手动优化 Lucene 索引的方法。你可以在应用程序中的任何你喜欢的事件上调用这些方法。或者，你可能会公开它们，并从应用程序外部触发优化（例如，通过一个由夜间 cron 作业调用的 web 服务）。

您可以通过`FullTextSession`对象的`getSearchFactory`方法获得一个`SearchFactory`引用。一旦你有了这个实例，它的`optimize`方法将会碎片化所有可用的 Lucene 索引：

```java
...
fullTextSession.getSearchFactory().optimize();
...
```

另外，您可以使用一个带有实体类参数的`optimize`重载版本。这个方法将优化限制在只对该实体的 Lucene 索引进行优化，如下所示：

```java
...
fullTextSession.getSearchFactory().optimize(App.class);
...
```

### 注意

另一个选择是使用`MassIndexer`重新构建你的 Lucene 索引（参考*大规模更新*部分）。从零开始重建索引无论如何都会使其处于优化状态，所以如果你已经定期执行这种类型的维护工作，进一步的优化将是多余的。

一个*非常*手动的方法是使用 Luke 工具，完全不在你的应用程序代码中。请参阅本章末尾关于 Luke 的部分。

## 自动优化

一个更简单，但灵活性较低的方法是让 Hibernate Search 自动为你触发优化。这可以全局或针对每个索引执行。触发事件可以是 Lucene 更改的阈值数量，或者事务的阈值数量。

VAPORware Marketplace 应用程序的`chapter6`版本现在在其`hibernate.cfg.xml`文件中包含了以下四行：

```java
<property name="hibernate.search.default.optimizer.operation_limit.max">
   1000
</property>
<property name="hibernate.search.default.optimizer.transaction_limit.max">
   1000
</property>
<property name="hibernate.search.App.optimizer.operation_limit.max">
   100
</property>
<property name="hibernate.search.App.optimizer.transaction_limit.max">
   100
</property>
```

最上面的两行，在属性名称中引用`default`，为所有 Lucene 索引建立了全局默认值。最后两行，引用`App`，是针对`App`实体的覆盖值。

### 注意

本章中的大多数配置属性可以通过将`default`子字符串替换为相关索引的名称，使其变为索引特定。

通常这是实体类的名称（例如，`App`），但如果你设置了该实体的`@Indexed`注解中的`index`元素，它也可以是一个自定义名称。

无论你是在全局还是索引特定级别操作，`operation_limit.max`指的是 Lucene 更改（即添加或删除）的阈值数量。`transaction_limit.max`指的是事务的阈值数量。

总的来说，此代码段配置了在 100 个事务或 Lucene 更改后对`App`索引进行优化。所有其他索引将在 1,000 个事务或更改后进行优化。

### 自定义优化器策略

你可以通过使用带有自定义优化策略的自动方法，享受到两全其美。本章的 VAPORware Marketplace 应用程序使用自定义策略，只在非高峰时段允许优化。这个自定义类扩展了默认优化器策略，但只允许在当前时间在午夜至凌晨 6 点之间时，基类进行优化：

```java
public class NightlyOptimizerStrategy
      extendsIncrementalOptimizerStrategy {

 @Override
 public void optimize(Workspace workspace) {
      Calendar calendar = Calendar.getInstance();
      inthourOfDay = calendar.get(Calendar.HOUR_OF_DAY);
      if(hourOfDay>= 0 &&hourOfDay<= 6) {
 super.optimize(workspace);
      }
   }

}
```

### 提示

最简单的方法是扩展`IncrementalOptimizerStrategy`，并用你的拦截逻辑覆盖`optimize`方法。然而，如果你的策略与默认策略根本不同，那么你可以从自己的基类开始。只需让它实现`OptimizerStrategy`接口。

为了声明你自己的自定义策略，无论是在全局还是每个索引级别，都需要在`hibernate.cfg.xml`中添加一个`hibernate.search.X.optimizer.implementation`属性（其中*X*是*default*，或者是特定实体索引的名称）：

```java
...
<property name="hibernate.search.default.optimizer.implementation">
com.packtpub.hibernatesearch.util.NightlyOptimizerStrategy
</property>
...
```

# 选择索引管理器

**索引管理器**是一个负责将更改应用到 Lucene 索引的组件。它协调优化策略、目录提供者以及工作者后端（在本章后面部分介绍），还有各种其他底层组件。

休眠搜索自带两种索引管理器实现。默认的是基于`directory-based`的，在大多数情况下这是一个非常合理的选择。

另一个内置选项是**近实时**。它是一个从基于目录的索引管理器派生的子类，但设计用于低延迟的索引写入。而不是立即在磁盘上执行添加或删除，这个实现将它们排队在内存中，以便更有效地批量写入。

### 注意

**近实时**实现比基于目录的默认实现具有更好的性能，但有两个权衡。首先，当在集群环境中使用 Lucene 时，**近实时**实现是不可用的（参考第七章，*高级性能策略*）。其次，由于 Lucene 操作不会立即写入磁盘，因此在应用程序崩溃的情况下可能会永久丢失。

与本章中介绍的大多数配置属性一样，索引管理器可以在全局默认或每索引的基础上选择。区别在于是否包括`default`，或者实体索引名称（例如，`App`）在属性中：

```java
...
<property name="hibernate.search.default.indexmanager">
   directory-based
</property>
<property name="hibernate.search.App.indexmanager">
   near-real-time
</property>
...
```

可以编写自己的索引管理器实现。为了更深入地了解索引管理器是如何工作的，请查看提供的两个内置实现源代码。基于目录的管理器由`DirectoryBasedIndexManager`实现，近实时管理器由`NRTIndexManager`实现。

### 提示

编写自定义实现的一种简单方法是继承两个内置选项中的一个，并根据需要重写方法。如果您想从头开始创建自定义索引管理器，那么它需要实现`org.hibernate.search.indexes.spi.IndexManager`接口。

在全局或每索引级别应用自定义索引管理器与内置选项相同。只需将适当的属性设置为您的实现的全限定类名（例如，`com.packtpub.hibernatesearch.util.MyIndexManager`），而不是`directory-based`或`near-real-time`字符串。

# 配置工作者

索引管理器协调的组件类型之一是**工作者**，它们负责对 Lucene 索引进行实际的更新。

如果您在集群环境中使用 Lucene 和 Hibernate Search，许多配置选项是在工作者级别设置的。我们将在第七章，*高级性能策略*中更全面地探讨这些内容。然而，在任何环境中都提供了三个关键的配置选项。

## 执行模式

默认情况下，工作者执行 Lucene 更新**同步**。也就是说，一旦开始更新，主线的执行就会被阻塞，直到更新完成。

工人可能被配置为以**异步**方式更新，这是一种“启动并忘记”的模式，它会创建一个单独的线程来执行工作。优点是主线程将更具响应性，且能更高效地处理工作负载。缺点是在非常短暂的时间内数据库和索引可能会不同步。

执行模式在`hibernate.cfg.xml`（或`persistence.xml`对于 JPA）中声明。可以用`default`子字符串建立全局默认值，而每个实体的配置可以用实体索引名称（例如，`App`）来设置：

```java
...
<property name="hibernate.search.default.worker.execution">
   sync
</property>
<property name="hibernate.search.App.worker.execution">
   async
</property>
...
```

## 线程池

默认情况下，工人在只有一个线程中更新，要么是同步模式下的主线程，要么是异步模式下单独创建的一个线程。然而，你有创建一个更大线程池来处理工作的选项。这个池可能适用于全局默认级别，也可能特定于某个索引：

```java
...
<property name="hibernate.search.default.worker.thread_pool.size">
   2
</property>
<property name="hibernate.search.App.worker.thread_pool.size">
   5
</property>
...
```

### 提示

由于 Lucene 索引在更新操作期间以这种方式被锁定，使用许多并行线程通常不会提供你可能会期望的性能提升。然而，在调整和负载测试应用程序时尝试是有价值的。

## 缓冲队列

挂起的工作会保存在队列中，等待线程空闲时处理。默认情况下，这个缓冲区的大小是无限的，至少在理论上如此。实际上，它受到可用系统内存量的限制，如果缓冲区增长过大，可能会抛出`OutOfMemoryExeception`。

因此，为这些缓冲区设置一个全局大小或每个索引大小的限制是一个好主意。

```java
...
<property name="hibernate.search.default.worker.buffer_queue.max">
   50
</property>
<property name="hibernate.search.App.worker.buffer_queue.max">
   250
</property>
...
```

当一个缓冲区达到其索引允许的最大大小时，将由创建它们的线程执行额外操作。这会阻塞执行并减慢性能，但确保应用程序不会运行 out of memory。实验找到一个应用程序的平衡阈值。

# 选择和配置目录提供程序

内置的索引管理器都使用了一个子类`DirectoryBasedIndexManager`。正如其名，它们都利用了 Lucene 的抽象类`Directory`，来管理索引存储的形式。

在第七章中，我们将探讨一些特殊目录实现，这些实现是为集群环境量身定做的。然而，在单服务器环境中，内置的两种选择是文件系统存储和内存中的存储。

## Filesystem-based

默认情况下，Lucene 索引存储在 Java 应用程序的当前工作目录中。对于这种安排，无需进行任何配置，但在 VAPORware Marketplace 应用程序的所有版本中，都明确设置了这个属性在`hibernate.cfg.xml`（或`persistence.xml`）中：

```java
...
<property name="hibernate.search.default.directory_provider">
   filesystem
</property>
...
```

正如我们在本章中看到的其他配置属性一样，你可以用特定的索引名称（例如，`App`）替换`default`。

当使用基于文件系统的索引时，您可能希望使用一个已知的固定位置，而不是当前工作目录。您可以使用 `indexBase` 属性指定相对路径或绝对路径。在我们见过的所有 VAPORware Marketplace 版本中，Lucene 索引都存储在每个 Maven 项目的 `target` 目录下，这样 Maven 在每次全新构建之前会删除它们：

```java
...
<property name="hibernate.search.default.indexBase">
   target/lucenceIndex
</property>
...
```

### 锁策略

所有 Lucene 目录实现当向其写入时都会锁定它们的索引，以防止多个进程或线程同时向其写入导致的损坏。有四种锁策略可供选择，您可以通过将 `hibernate.search.default.locking_strategy` 属性设置为这些字符串之一来指定一个：

+   `native`: 当没有指定锁策略属性时，基于文件系统的目录默认采用的策略。它依赖于本地操作系统级别的文件锁，因此如果您的应用程序崩溃，索引锁仍然会被释放。然而，这种策略不适用于您的索引存储在远程网络共享驱动器上时。

+   `simple`: 这种策略依赖于 JVM 来处理文件锁。当您的 Lucene 索引存储在远程共享驱动器上时，使用这种策略更安全，但如果应用程序崩溃或被杀死，锁不会被干净地释放。

+   `single`: 这种策略不会在文件系统上创建锁文件，而是使用内存中的 Java 对象（类似于多线程 Java 代码中的 `synchronized` 块）。对于单 JVM 应用程序，无论索引文件在哪里，这种方法都工作得很好，而且在崩溃后没有锁被释放的问题。然而，这种策略只有在您确信没有任何其他外部 JVM 进程可能会写入您的索引文件时才是可行的。

+   `none`: 根本不使用锁。这不是一个推荐的选项。

### 提示

为了删除未干净释放的锁，请使用本章*使用 Luke 工具*部分探索的 Luke 工具。

## 基于 RAM

出于测试和演示目的，我们这本书中的 VAPORware Marketplace 应用程序一直使用内存中的 H2 数据库。每次应用程序启动时都会重新创建它，应用程序停止时会摧毁它，在此过程中没有任何持久化存储。

Lucene 索引能够以完全相同的方式工作。在本章示例应用程序的版本中，`hibernate.cfg.xml` 文件已经被修改以将其索引存储在 RAM 中，而不是文件系统上：

```java
...
<property name="hibernate.search.default.directory_provider">
   ram
</property>
...
```

### 注意

基于 RAM 的目录提供者在其 Hibernate `SessionFactory`（或 JPA `EntityManagerFactory`）创建时初始化其 Lucene 索引。请注意，当你关闭这个工厂时，它会摧毁你所有的索引！

使用现代依赖注入框架时，这不应该是一个问题，因为框架会在内存中保持您的工厂实例，并在需要时可用。即使在我们的基础示例应用程序中，我们也为此原因在 `StartupDataLoader` 类中存储了一个单例 `SessionFactory`。

内存中的索引似乎能提供更好的性能，在您的应用程序调整中尝试一下可能是值得的。然而，通常不建议在生产环境中使用基于 RAM 的目录提供程序。

首先，当数据集很大时，很容易耗尽内存并导致应用程序崩溃。另外，每次重新启动时，您的应用程序都必须从头开始重建索引。由于只有创建内存索引的 JVM 才能访问该内存，因此无法使用集群。最后但同样重要的是，基于文件系统的目录提供程序已经智能地使用了缓存，其性能出奇地与基于 RAM 的提供程序相当。

话虽如此，基于 RAM 的提供程序是测试应用程序的常见方法。单元测试可能涉及相对较小的数据集，因此耗尽内存不是问题。另外，在每次单元测试之间完全且干净地销毁索引可能更是一个特性而非缺点。

### 提示

基于 RAM 的目录提供程序默认使用 `single` 锁定策略，而且真的没有改变它的意义。

# 使用 Luke 工具

Hibernate ORM 为您的应用程序代码提供了与数据库交互所需的大部分功能。然而，您可能仍然需要使用某种 SQL 客户端，在应用程序代码的上下文之外手动操作数据库。

同样，在没有编写相关代码的情况下手动探索 Lucene 索引可能很有用。Luke（[`code.google.com/p/luke`](http://code.google.com/p/luke)）是一个非常有用的工具，它为 Lucene 提供了这一功能。您可以使用 Luke 浏览索引、测试查询，并执行诸如删除未正常释放的索引锁等有用任务。

Luke 的下载文件是一个单片式的可执行 JAR 文件。双击 JAR 文件，或者从控制台提示符执行它，会弹出一个图形界面和一个提示您索引位置的输入框，如下面的屏幕快照所示：

![使用 Luke 工具](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205_06_01.jpg)

前一个屏幕快照显示了 Luke 启动时的界面。不幸的是，Luke 只能访问基于文件系统的索引，而不能访问本章中使用基于 RAM 的索引。所以在这段示例中，Luke 指向了 `chapter5` 代码文件目录的 Maven 项目工作区。`App` 实体的索引位于 `target/luceneIndex/com.packtpub.hibernatesearch.domain.App`。

请注意打开索引对话框顶部附近的**强制解锁，如果** **锁定**复选框。如果您有一个索引文件锁没有干净释放（参考*锁定策略*部分），则可以通过勾选此复选框并打开索引来解决问题。

一旦您打开了一个 Lucene 索引，Luke 就会显示关于索引文档（即实体）数量的各类信息（即，碎片化）和其他详细信息，如下面的屏幕截图所示：

![使用 Luke 工具](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205_06_02.jpg)

从工具栏顶部的**工具**菜单中，您可以选择执行诸如检查索引是否损坏或手动优化（即，去碎片化）等基本维护任务。这些操作最好在非高峰时段或全面停机窗口期间执行。

![使用 Luke 工具](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205_06_03.jpg)

**文档**标签允许您逐一浏览实体，这可能有一些有限的用途。更有趣的是**搜索**标签，它允许您使用自由形式的 Lucene 查询来探索您的索引，如下面的屏幕截图所示：

![使用 Luke 工具](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205_06_04.jpg)

完整的 Lucene API 超出了本书的范围，但这里有一些基础知识来帮助您入门：

+   搜索表达式的形式是字段名和期望值，由冒号分隔。例如，要搜索`business`类别的应用程序，请使用搜索表达式`category:business`。

+   相关项目可以用实体字段名，后跟一个点，后跟相关项目内的字段名来指定。在上面的屏幕截图中，我们通过使用搜索表达式`supportedDevices.name:xphone`来搜索所有支持`xPhone`设备的应用程序。

+   记住，默认分析器在索引过程中将术语转换为小写。所以如果你想搜索`xPhone`，例如，请确保将其输入为`xphone`。

如果您双击找到的搜索结果之一，Luke 会切换到**文档**标签，并加载相关文档。点击**重建&编辑**按钮来检查该实体的字段，如下面的屏幕截图所示：

![使用 Luke 工具](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205_06_05.jpg)

浏览这些数据将让您了解分析器如何解析您的实体。单词将被过滤掉，除非您配置了`@Field`注解相反（正如我们用`sorting_name`所做的那样），否则文本将被分词。如果 Hibernate Search 查询没有返回您期望的结果，Luke 中浏览字段数据可以帮助您发现问题。

# 摘要

在本章中，我们了解了如何手动更新 Lucene 索引，一次一个实体对象或批量更新，作为让 Hibernate Search 自动管理更新的一种替代方式。我们了解了 Lucene 更新操作积累的碎片，以及如何基于手动或自动方法进行优化。

我们探索了 Lucene 的各种性能调优选项，从低延迟写入到多线程异步更新。我们现在知道如何配置 Hibernate Search，在文件系统或 RAM 上创建 Lucene 索引，以及为什么您可能会选择其中之一。最后，我们使用 Luke 工具来检查和执行维护任务，而无需通过应用程序的 Hibernate Search 代码来操作 Lucene 索引。

在下一章中，我们将探讨一些高级策略，以提高您的应用程序的性能。这将包括回顾到目前为止介绍的性能提示，然后深入探讨服务器集群和 Lucene 索引分片。


# 第七章 高级性能策略

在本章中，我们将探讨一些高级策略，通过代码以及服务器架构来提高生产应用程序的性能和可伸缩性。我们将探讨运行应用程序的多节点服务器集群选项，以分布式方式分散和处理用户请求。我们还将学习如何使用分片来使我们的 Lucene 索引更快且更易于管理。

# 通用建议

在深入探讨一些提高性能和可伸缩性的高级策略之前，让我们简要回顾一下书中已经提到的某些通用性能优化建议。

+   当为 Hibernate Search 映射实体类时，使用`@Field`注解的可选元素去除 Lucene 索引中的不必要膨胀（参见第二章，*映射实体类*）：

    +   如果你确实不使用索引时提升（参见第四章，*高级映射*），那么就没有理由存储实现此功能所需的信息。将`norms`元素设置为`Norms.NO`。

    +   默认情况下，除非将`store`元素设置为`Store.YES`或`Store.COMPRESS`（参见第五章，*高级查询*），否则基于投影的查询所需的信息不会被存储。如果你有不再使用的基于投影的查询，那么在进行清理时删除这个元素。

+   使用条件索引（参见第四章，*高级映射*）和部分索引（参见第二章，*映射实体类*）来减小 Lucene 索引的大小。

+   依赖于过滤器在 Lucene 层面缩小结果，而不是在数据库查询层面使用`WHERE`子句（参见第五章，*高级查询*）。

+   尽可能尝试使用基于投影的查询（参见第五章，*高级查询*），以减少或消除对数据库调用的需求。请注意，随着数据库缓存的提高，这些好处可能并不总是值得增加的复杂性。

+   测试各种索引管理器选项（参见第六章，*系统配置和索引管理*），例如尝试近实时索引管理器或`async`工作执行模式。

# 在集群中运行应用程序

在生产环境中使现代 Java 应用程序扩展通常涉及在服务器实例的集群中运行它们。Hibernate Search 非常适合集群环境，并提供了多种配置解决方案的方法。

## 简单集群

最直接的方法需要非常少的 Hibernate Search 配置。只需为托管您的 Lucene 索引设置一个文件服务器，并使其可供您集群中的每个服务器实例使用（例如，NFS、Samba 等）：

![简单集群](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9207OS_07_01.jpg)

具有多个服务器节点的简单集群，使用共享驱动上的公共 Lucene 索引

集群中的每个应用程序实例都使用默认的索引管理器，以及常用的`filesystem`目录提供程序（参见第六章，*系统配置和索引管理*）。

在这种安排中，所有的服务器节点都是真正的对等节点。它们各自从同一个 Lucene 索引中读取，无论哪个节点执行更新，那个节点就负责写入。为了防止损坏，Hibernate Search 依赖于锁定策略（即“简单”或“本地”，参见第六章，*系统配置和索引管理*)同时写入被阻止。

### 提示

回想一下，“近实时”索引管理器与集群环境是不兼容的。

这种方法的优点是两方面的。首先是简单性。涉及的步骤仅包括设置一个文件系统共享，并将每个应用程序实例的目录提供程序指向同一位置。其次，这种方法确保 Lucene 更新对集群中的所有节点立即可见。

然而，这种方法的严重缺点是它只能扩展到一定程度。非常小的集群可能运行得很好，但是尝试同时访问同一共享文件的更多节点最终会导致锁定争用。

另外，托管 Lucene 索引的文件服务器是一个单点故障。如果文件共享挂了，那么在整个集群中的搜索功能会立即灾难性地崩溃。

## 主从集群

当您的可扩展性需求超出简单集群的限制时，Hibernate Search 提供了更高级别的模型供您考虑。它们之间的共同点是主节点负责所有 Lucene 写操作的理念。

集群还可能包括任何数量的从节点。从节点仍然可以初始化 Lucene 更新，应用程序代码实际上无法区分。然而，在底层，从节点将这项工作委托给主节点实际执行。

### 目录提供程序

在主从集群中，仍然有一个“总体主”Lucene 索引，它在逻辑上与所有节点区分开来。这个索引可能是基于文件系统的，正如它在一个简单集群中一样。然而，它可能是基于 JBoss Infinispan（[`www.jboss.org/infinispan`](http://www.jboss.org/infinispan)），一个由同一公司主要赞助 Hibernate 开发的开源内存中 NoSQL 数据存储：

+   在**基于文件系统的**方法中，所有节点都保留它们自己的 Lucene 索引的本地副本。主节点实际上在整体主索引上执行更新，所有节点定期从那个整体主索引中读取以刷新它们的本地副本。

+   在**Infinispan 基于**的方法中，所有节点都从 Infinispan 索引中读取（尽管仍然建议将写操作委派给主节点）。因此，节点不需要维护它们自己的本地索引副本。实际上，由于 Infinispan 是一个分布式数据存储，索引的某些部分将驻留在每个节点上。然而，最好还是将整个索引视为一个单独的实体。

### 工作端后端

奴隶节点将写操作委派给主节点的两种可用机制：

+   **JMS**消息队列提供程序创建一个队列，奴隶节点将有关 Lucene 更新请求的详细信息发送到这个队列。主节点监控这个队列，检索消息，并实际执行更新操作。

+   您可以选择用**JGroups**（[`www.jgroups.org`](http://www.jgroups.org)）替换 JMS，这是一个用于 Java 应用程序的开源多播通信系统。它的优点是速度更快，更立即。消息实时接收，同步而不是异步。

    然而，JMS 消息通常在等待检索时持久化到磁盘上，因此可以在应用程序崩溃的情况下恢复并稍后处理。如果您使用 JGroups 并且主节点离线，那么在停机期间奴隶节点发送的所有更新请求都将丢失。为了完全恢复，您可能需要手动重新索引您的 Lucene 索引。

    ![Worker backends](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9207OS_07_02.jpg)

    一个基于文件系统或 Infinispan 的目录提供程序和基于 JMS 或 JGroups 的工作程序的主从集群。请注意，当使用 Infinispan 时，节点不需要它们自己的单独索引副本。

### 一个工作示例

要尝试所有可能的集群策略，需要查阅 Hibernate Search 参考指南，以及 Infinispan 和 JGroups 的文档。然而，我们将从实现使用文件系统和 JMS 方法的集群开始，因为其他所有内容都只是这个标准主题的变体。

本章版本的 VAPORware Marketplace 应用摒弃了我们一直使用的 Maven Jetty 插件。这个插件非常适合测试和演示目的，但它只适用于运行单个服务器实例，而我们现在需要同时运行至少两个 Jetty 实例。

为了实现这一点，我们将以编程方式配置和启动 Jetty 实例。如果你在`chapter7`项目的`src/test/java/`目录下查看，现在有一个`ClusterTest`类。它为 JUnit 4 设计，以便 Maven 可以在构建后自动调用其`testCluster()`方法。让我们看看那个测试用例方法的相关部分：

```java
...
String projectBaseDirectory = System.getProperty("user.dir");
...
Server masterServer = new Server(8080);
WebAppContextmasterContext = new WebAppContext();
masterContext.setDescriptor(projectBaseDirectory +
   "/target/vaporware/WEB-INF/web.xml");
...
masterServer.setHandler(masterContext);
masterServer.start();
...
Server slaveServer = new Server(8181);
WebAppContextslaveContext = new WebAppContext();
slaveContext.setDescriptor(projectBaseDirectory +
   "/target/vaporware/WEB-INF/web-slave.xml");
...
slaveServer.setHandler(slaveContext);
slaveServer.start();
...
```

尽管所有这些都在一台物理机器上运行，但我们为了测试和演示目的模拟了一个集群。一个 Jetty 服务器实例在端口 8080 上作为主节点启动，另一个 Jetty 服务器在端口 8181 上作为从节点启动。这两个节点之间的区别在于，它们使用不同的`web.xml`文件，在启动时相应地加载不同的监听器。

在这个应用程序的先前版本中，一个`StartupDataLoader`类处理了所有数据库和 Lucene 的初始化。现在，两个节点分别使用`MasterNodeInitializer`和`SlaveNodeInitializer`。这些依次从名为`hibernate.cfg.xml`和`hibernate-slave.cfg.xml`的不同文件加载 Hibernate ORM 和 Hibernate Search 设置。

### 提示

有许多方法可以配置一个应用程序以作为主节点或从节点实例运行。而不是构建不同的 WAR，具有不同的`web.xml`或`hibernate.cfg.xml`版本，你可能会使用依赖注入框架根据环境中的某个内容加载正确的设置。

Hibernate 的两种版本都设置了`config`文件中的以下 Hibernate Search 属性：

+   `hibernate.search.default.directory_provider`：在之前的章节中，我们看到这个属性被设置为`filesystem`或`ram`。之前讨论过的另一个选项是`infinispan`。

    在这里，我们在主节点和从节点上分别使用`filesystem-master`和`filesystem-slave`。这两个目录提供者都与常规的`filesystem`类似，并且与迄今为止我们看到的所有相关属性（如位置、锁定策略等）一起工作。

    然而，“主”变体包含了定期刷新整体主 Lucene 索引的功能。而“从”变体则相反，定期用整体主内容刷新其本地副本。

+   `hibernate.search.default.indexBase`：正如我们之前在单节点版本中看到的，这个属性包含了*本地* Lucene 索引的基础目录。由于我们这里的示例集群在同一台物理机器上运行，主节点和从节点对这个属性使用不同的值。

+   `hibernate.search.default.sourceBase`：这个属性包含了*整体主* Lucene 索引的基础目录。在生产环境中，这将是某种共享文件系统，挂在并可供所有节点访问。在这里，节点在同一台物理机器上运行，所以主节点和从节点对这个属性使用相同的值。

+   `hibernate.search.default.refresh`：这是索引刷新之间的间隔（以秒为单位）。主节点在每个间隔后刷新整体主索引，奴隶节点使用整体主索引刷新它们自己的本地副本。本章的 VAPORware Marketplace 应用程序使用 10 秒的设置作为演示目的，但在生产环境中这太短了。默认设置是 3600 秒（一小时）。

为了建立一个 JMS 工作后端，奴隶节点*仅*需要三个额外的设置：

+   `hibernate.search.default.worker.backend`：将此值设置为`jms`。默认值`lucene`在之前的章节中已经应用，因为没有指定设置。如果你使用 JGroups，那么它将被设置为`jgroupsMaster`或`jgroupsSlave`，这取决于节点类型。

+   `hibernate.search.default.worker.jms.connection_factory`：这是 Hibernate Search 在 JNDI 中查找你的 JMS 连接工厂的名称。这与 Hibernate ORM 使用`connection.datasource`属性从数据库检索 JDBC 连接的方式类似。

    在这两种情况下，JNDI 配置都是特定于你的应用程序运行的应用服务器。要了解 JMS 连接工厂是如何设置的，请查看`src/main/webapp/WEB-INF/jetty-env.xml`这个 Jetty 配置文件。在这个示例中我们使用 Apache ActiveMQ，但任何兼容 JMS 的提供商都会同样适用。

+   `hibernate.search.default.worker.jms.queue`：从奴隶节点向 Lucene 发送写请求的 JMS 队列的 JNDI 名称。这也是在应用服务器级别配置的，紧挨着连接工厂。

使用这些工作后端设置，奴隶节点将自动向 JMS 队列发送一条消息，表明需要 Lucene 更新。为了看到这种情况的发生，新的`MasterNodeInitializer`和`SlaveNodeInitializer`类各自加载了一半的通常测试数据集。如果我们所有的测试实体最终都被一起索引，并且可以从任一节点运行的搜索查询中检索到它们，那么我们就会知道我们的集群运行正常。

尽管 Hibernate Search 会自动从奴隶节点向 JMS 队列发送消息，但让主节点检索这些消息并处理它们是你的责任。

在 JEE 环境中，你可能会使用消息驱动 bean，正如 Hibernate Search 文档所建议的那样。Spring 也有一个可以利用的任务执行框架。然而，在任何框架中，基本思想是主节点应该产生一个后台线程来监控 JMS 队列并处理其消息。

本章的 VAPORware Marketplace 应用程序包含一个用于此目的的`QueueMonitor`类，该类被包装在一个`Thread`对象中，由`MasterNodeInitializer`类产生。

要执行实际的 Lucene 更新，最简单的方法是创建您自己的自定义子类`AbstractJMSHibernateSearchController`。我们的实现称为`QueueController`，所做的只是包装这个抽象基类。

当队列监视器从 JMS 队列中接收到`javax.jms.Message`对象时，它只是原样传递给控制器的基类方法`onMessage`。那个内置方法为我们处理 Lucene 更新。

### 注意

正如您所看到的，主从集群方法涉及的内容比简单集群要多得多。然而，主从方法在可扩展性方面提供了巨大的优势。

它还减少了单点故障的风险。确实，这种架构涉及一个单一的“主”节点，所有 Lucene 写操作都必须通过这个节点。然而，如果主节点宕机，从节点仍然可以继续工作，因为它们的搜索查询针对的是自己的本地索引副本。此外，更新请求应该由 JMS 提供商持久化，以便在主节点重新上线后，这些更新仍然可以执行。

由于我们程序化地启动 Jetty 实例，而不是通过 Maven 插件，因此我们将不同的目标传递给每个 Maven 构建。对于`chapter7`项目，您应该像以下这样运行 Maven：

```java
mvn clean compile war:exploded test
```

您将能够通过`http://localhost:8080`访问“主”节点，通过`http://localhost:8181`访问“从”节点。如果您在主节点启动后立即发送一个搜索查询，那么您将看到它只返回预期结果的一半！然而，在几秒钟内，从节点通过 JMS 更新。数据集的两个部分将合并并在整个集群中可用。

# 分片 Lucene 索引

正如您可以在集群中的多个节点之间平衡应用程序负载一样，您还可以通过一个称为**分片（sharding）**的过程将 Lucene 索引拆分。如果您的索引变得非常大，出于性能原因，您可能会考虑进行分片，因为较大的索引文件比小型分片索引和优化需要更长的时间。

如果您的实体适合于分区（例如，按语言、地理区域等），分片可能会提供额外的优势。如果您能够可预测地将查询引导到特定的适当分片，性能可能会得到改善。此外，当您能够在物理位置不同的地方存储“敏感”数据时，有时会让律师感到高兴。

尽管它的数据集非常小，但本章的 VAPORware Marketplace 应用程序现在将其`App`索引分成两个分片。`hibernate.cfg.xml`中的相关行类似于以下内容：

```java
...
<property
   name="hibernate.search.default.sharding_strategy.nbr_of_shards">
      2
</property>
...
```

与所有包含子字符串`default`的其他 Hibernate Search 属性一样，这是一个全局设置。可以通过用索引名称（例如`App`）替换`default`来使其特定于索引。

### 注意

这个确切的行出现在`hibernate.cfg.xml`（由我们的“主”节点使用）和`hibernate-slave.cfg.xml`（由我们的“从”节点使用）中。在集群环境中运行时，你的分片配置应与所有节点匹配。

当一个索引被分成多个分片时，每个分片都包括正常的索引名称后面跟着一个数字（从零开始）。例如，是`com.packtpub.hibernatesearch.domain.App.0`，而不仅仅是`com.packtpub.hibernatesearch.domain.App`。这张截图展示了我们双节点集群的 Lucene 目录结构，在两个节点都配置为两个分片的情况下运行中：

![分片 Lucene 索引](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205_07_03.jpg)

集群中运行的分片 Lucene 索引的一个示例（注意每个`App`实体目录的编号）

正如分片在文件系统上编号一样，它们可以在`hibernate.cfg.xml`中按编号单独配置。例如，如果你想将分片存储在不同的位置，你可能如下设置属性：

```java
...
<property name="hibernate.search.App.0.indexBase">
   target/lucenceIndexMasterCopy/EnglishApps
</property>
<property name="hibernate.search.App.1.indexBase">
   target/lucenceIndexMasterCopy/FrenchApps
</property>
...
```

当对实体执行 Lucene 写操作时，或者当搜索查询需要从实体的索引中读取时，**分片策略**确定使用哪个分片。

如果你只是分片以减少文件大小，那么默认策略（由`org.hibernate.search.store.impl.IdHashShardingStrategy`实现）完全没问题。它使用每个实体的 ID 来计算一个唯一的哈希码，并将实体在分片之间大致均匀地分布。因为哈希计算是可复制的，策略能够将实体的未来更新引导到适当的分片。

要创建具有更复杂逻辑的自定义分片策略，你可以创建一个新子类，继承自`IdHashShardingStrategy`，并按需调整。或者，你可以完全从零开始，创建一个实现`org.hibernate.search.store.IndexShardingStrategy`接口的新类，或许可以参考`IdHashShardingStrategy`的源代码作为指导。

# 总结

在本章中，我们学习了如何在现代分布式服务器架构中与应用程序一起工作，以实现可扩展性和更好的性能。我们看到了一个使用基于文件系统的目录提供程序和基于 JMS 的后端实现的集群，现在有了足够的知识去探索涉及 Inifinispan 和 JGroups 的其他方法。我们使用了分片将 Lucene 索引分成更小的块，并知道如何实施自己的自定义分片策略。

这带我们结束了与 Hibernate Search 的这次小冒险！我们已经涵盖了关于 Hibernate、Lucene 和 Solr 以及搜索的一般性关键概念。我们学会了如何将我们的数据映射到搜索索引中，在运行时查询和更新这些索引，并将其安排在给定项目的最佳架构中。这一切都是通过一个示例应用程序完成的，这个应用程序随着我们的知识从简单到复杂一路成长。

学无止境。Hibernate Search 可以与 Solr 的数十个组件协同工作，以实现更高级的功能，同时也能与新一代的“NoSQL”数据存储集成。然而，现在你已经拥有了足够的核心知识，可以独立探索这些领域，如果你愿意的话。下次再见，感谢您的阅读！您可以在 `steveperkins.net` 上找到我，我很乐意收到您的来信。
