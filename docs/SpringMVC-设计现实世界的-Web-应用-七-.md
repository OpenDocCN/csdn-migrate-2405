# SpringMVC：设计现实世界的 Web 应用（七）

> 原文：[`zh.annas-archive.org/md5/AB3510E97B9E20602840C849773D49C6`](https://zh.annas-archive.org/md5/AB3510E97B9E20602840C849773D49C6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：实施 HATEOAS

本章包含以下配方：

+   将 DTO 转换为 Spring HATEOAS 资源

+   为超媒体驱动的 API 构建链接

+   选择暴露 JPA 实体的策略

+   使用 OAuth 从第三方 API 检索数据

# 介绍

什么是 HATEOAS？如果你以前从未见过这个词，它可能很难发音。有些人发音为 hate-ee-os；其他人说 hate O-A-S。重要的是要记住这个缩写代表**超媒体作为应用状态的引擎**（**HATEOAS**）。至少，你应该记住超媒体。超媒体作为资源嵌入节点，指向外部资源的能力。作为与其他资源连接的资源，超媒体资源也受到其领域的限制，因为它在技术上不能开发其他资源的领域（作为其一部分）。

把它想象成**维基百科**。如果我们创建一个页面，其各个部分不是在页面标题（域）中自包含的，如果其中一个部分已经在外部页面中涵盖，那么管理员几乎不可能提出这种情况。

HATEOAS 是适用于 REST 架构的约束。它对其资源施加域一致性，并同时对所有权者施加明确的自我文档化，以维护整体凝聚力。

## Richardson 成熟度模型

Richardson 成熟度模型（Leonard Richardson 编写）提供了一种通过 REST 约束级别对 REST API 进行评分和资格认定的方法：

![Richardson 成熟度模型](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00882.jpeg)

API 越符合 REST 标准，评分越高。

该模型中的初始状态是**Level 0**：**POX 的沼泽**。在这里，协议（通常是 HTTP）仅用于其传输功能（而不是用于其状态描述功能）。此外，这里没有特定于资源的 URI，只使用一个端点用于一个方法（通常是 HTTP 中的`POST`）。

**Level 1: 资源**的特征是实现特定于资源的 URI。资源标识符可以在 URI 中找到。然而，仍然只使用协议的一个方法（再次是 HTTP 的 POST）。

**Level 2: HTTP 动词**反映了对协议属性的改进使用。对于 HTTP，这实际上意味着 API 正在使用 HTTP 方法来实现其目的（`GET`用于读取，`POST`用于创建，`PUT`用于编辑，`DELETE`用于删除等）。此外，API 提供可靠地通知用户有关操作状态的响应代码。

**Level 3: 超媒体控制**是该模型中的最高级别。它指示使用 HATEOAS，为客户端提供 API 发现功能。

您可以在 Martin Fowler 的博客上阅读有关 Richardson 成熟度模型的更多信息：

[`martinfowler.com/articles/richardsonMaturityModel.html`](http://martinfowler.com/articles/richardsonMaturityModel.html)

# 将 DTO 转换为 Spring HATEOAS 资源

本教程介绍了如何创建 Spring HATEOAS 资源。即使这里的重点是一个特定资源——`IndexResource`（代替以前的`IndexOverviewDTO`），也可以随意浏览**cloudstreetmarket-api**和**cloudstreetmarket-core**以发现更多更改。

HATEOAS 原则已应用于构成我们业务核心的所有资源，这在很大程度上反映了 Yahoo!的财务数据结构（指数、报价、产品、历史数据、图表等）。

## 如何做…

1.  从 Eclipse 的**Git Perspective**中，检出`v6.x.x`分支的最新版本。然后，在**cloudstreetmarket-parent**模块上运行`maven clean install`命令（右键单击**Run as…**下的**Maven Clean**菜单，然后再次单击**Run as…**下的**Maven Install**菜单），然后单击**Maven Update Project**菜单以将 Eclipse 与 Maven 配置同步（右键单击模块，然后导航到**Maven** | **Update Project…**）。

### 注意

此分支包括使用来自 Yahoo!的真实财务数据预填充数据库的 SQL 脚本。

1.  在拉取的更改中，一个新的`/app`配置目录出现在与`cloudstreetmarket-parent`和`zipcloud-parent`相同级别。必须将此`/app`目录复制到您系统的主目录：

+   将其复制到`C:\Users\{system.username}\app`，如果您使用的是 Windows

+   如果您使用的是 Linux，请将其复制到`/home/usr/{system.username}/app`

+   如果您使用的是 Mac OS X，请将其复制到`/Users/{system.username}/app`

1.  Spring HATEOAS 附带以下依赖项。此依赖项已添加到**cloudstreetmarket-parent**、**cloudstreetmarket-core**和**cloudstreetmarket-api**`：`

```java
<dependency>
  <groupId>org.springframework.hateoas</groupId>
  <artifactId>spring-hateoas</artifactId>
  <version>0.17.0.RELEASE</version>
</dependency>
```

1.  正如教程标题所示，目标是摆脱以前使用 REST API 公开的现有 DTO。目前，我们已删除了 IndexOverviewDTO、MarketOverviewDTO、ProductOverviewDTO 和 StockProductOverviewDTO。

1.  这些 DTO 已被这些类替换：IndexResource，StockProductResource，ChartResource，ExchangeResource，IndustryResource 和 MarketResource。

1.  正如所示的 IndexResource，它如下所示，所有这些新类都继承了 Spring HATEOAS Resource 类：

```java
@XStreamAlias("resource")
public class IndexResource extends Resource<Index> {
  public static final String INDEX = "index";
  public static final String INDICES = "indices";
  public static final String INDICES_PATH = "/indices";

  public IndexResource(Index content, Link... links) {
    super(content, links);
  }
}
```

1.  正如您所看到的，使用 IndexResource，资源是从 JPA 实体（这里是 Index.java）创建的。这些实体存储在资源超类型中的 content 属性名称下。

1.  我们已经将 JPA 实体转换为实现`Identifiable`接口的抽象类：

```java
@Entity
@Table(name="index_value")
@XStreamAlias("index")
public class Index extends ProvidedId<String> {

  private String name;

  @Column(name="daily_latest_value")
  private BigDecimal dailyLatestValue;

  @Column(name="daily_latest_change")
  private BigDecimal dailyLatestChange;

  @Column(name="daily_latest_change_pc")
  private BigDecimal dailyLatestChangePercent;

  @Column(name = "previous_close")
  private BigDecimal previousClose;

  private BigDecimal open;

  private BigDecimal high;

  private BigDecimal low;

  @ManyToOne(fetch = FetchType.EAGER)
  @JsonSerialize(using=IdentifiableSerializer.class)
  @JsonProperty("exchangeId")
  @XStreamConverter(value=IdentifiableToIdConverter.class, strings={"id"})
  @XStreamAlias("exchangeId")
   private Exchange exchange;

  @JsonIgnore
  @XStreamOmitField
  @ManyToMany(fetch = FetchType.LAZY)
  @JoinTable(name = "stock_indices", joinColumns = 
  {@JoinColumn(name = "index_code") },
  inverseJoinColumns = {@JoinColumn(name = "stock_code")})
  private Set<StockProduct> components = new LinkedHashSet<>();

  @Column(name="last_update", insertable=false, columnDefinition="TIMESTAMP DEFAULT CURRENT_TIMESTAMP")

  @Temporal(TemporalType.TIMESTAMP)
  private Date lastUpdate;

  public Index(){}

  public Index(String indexId) {
    setId(indexId);
  }

  //getters & setters

    @Override
    public String toString() {
    return "Index [name=" + name + ", dailyLatestValue=" + dailyLatestValue + ", dailyLatestChange=" + dailyLatestChange + ", dailyLatestChangePercent=" + dailyLatestChangePercent + ", previousClose=" + previousClose + ", open=" + open + ", high=" + high + ", low=" + low + ", exchange=" + exchange + ", lastUpdate=" + lastUpdate + ", id=" + id + "]";
    }
  }
```

1.  以下是 ProvidedId 类的详细信息，它是我们可识别实现中的一个：

```java
@MappedSuperclass
public class ProvidedId<ID extends Serializable> implements Identifiable<ID> {
  @Id 
  protected ID id;
  @Override
  public ID getId() {
    return id;
  }
  public void setId(ID id) {
    this.id = id;
  }
  @Override
  public String toString() {
    return id;
  }
  @Override
  public int hashCode() {
    return Objects.hash(id);
  }
  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    ProvidedId <?> other = (ProvidedId <?>) obj;
    return Objects.equals(this.id, other.id);
  }
}
```

## 它是如何工作的...

一个新的 Spring 依赖项，一些新的资源对象（Resource 子类），最后对我们的实体进行一些修改，以便它们实现`Identifiable`接口。让我们详细讨论所有这些。

### Spring HATEOAS 资源

正如在本章开头介绍的，HATEOAS 是关于链接的。可以说，作为框架的一部分，我们可以期望存在一种现有类型来支持和标准化链接的表示。

这就是`ResourceSupport`类（Spring HATEOAS 的一部分）的作用：支持附加到资源的链接的收集和管理。

另外，REST 资源也是一种内容。框架还提供了一个`Resource`类，它已经继承了`ResourceSupport`。

总之，使用 Spring HATEOAS，我们可以决定以两种不同的方式对我们的资源对象（`IndexResource`，`StockProductResource`等）进行建模：

+   我们可以通过直接让它们继承`ResourceSupport`来对它们进行建模。这样做的话，我们必须自己管理包装对象的资源内容。这里的内容对于框架来说是不受控制的。

+   我们还可以通过让它们继承泛型`Resource<T>`类来对它们进行建模，其中类型`T`对应于资源的`POJO`内容的类型。这是我们选择的策略。框架为我们的资源对象（`Inde3xResource`）提供了内容绑定、链接创建，甚至在控制器级别也是如此。我们很快就会看到这一切。

#### ResourceSupport 类

`ResourceSupport`类是一个实现`Identifiable<Link>`的对象：

```java
public class ResourceSupport extends Object implements Identifiable<Link>
```

以下是`ResourceSupport` JavaDoc 中的示例，它将为您提供有关其构造函数和方法的见解：

| 构造函数 |
| --- | --- |
| `ResourceSupport()` | 这将创建一个新的`ResourceSupport`类 |
| 方法 | 描述 |
| --- | --- |
| `Void add(Iterable<Link> links)` | 这将所有给定的链接添加到资源中 |
| `Void add(Link... links)` | 这将所有给定的链接添加到资源中 |
| `Void add(Link link)` | 这将添加给定的链接到资源中 |
| `Link getId()` | 这将返回具有`Link.REL_SELF`的`rel`的链接 |
| `Link getLink(String rel)` | 这将返回具有给定`rel`的链接 |
| `List<Link> getLinks()` | 这将返回资源中包含的所有链接 |
| `boolean hasLink(String rel)` | 这将返回资源是否包含具有给定`rel`的链接 |
| `boolean hasLinks()` | 这将返回资源是否包含链接 |
| `boolean removeLinks()` | 这将删除到目前为止添加到资源中的所有链接 |
| `Boolean equals(Object obj)` |   |
| `int hashCode()` |   |
| `String toString()` |   |

正如之前介绍的，这个类与链接有关！我们将看到 Spring HATEOAS 提供了围绕链接的一些小机制。

#### 资源类

`Resource`类是`POJO`的包装器。`POJO`存储在这个类的`content`属性中。`Resource`类本质上扩展了`ResourceSupport`：

```java
public class Resource<T> extends ResourceSupport
```

以下是`Resource` JavaDoc 中的示例，它提供了有关其构造函数和方法的见解：

| 构造函数 | 描述 |
| --- | --- |
| `Resource(T content, Iterable<Link> links)` | 这将使用给定的内容和链接创建一个新的资源 |
| `Resource(T content, Link... links)` | 这将使用给定的内容和链接（可选）创建一个新资源 |
| 方法 | 描述 |
| --- | --- |
| `TgetContent()` | 这将返回底层实体 |
| `void add(Iterable<Link> links)` | 这将所有给定的链接添加到资源中 |
| `void add(Link... links)` | 这将所有给定的链接添加到资源中 |
| `void add(Link link)` | 这将给定的链接添加到资源中 |
| `Link getId()` | 这将返回具有`Link.REL_SELF`的`rel`的链接 |
| `Link getLink(String rel)` | 这将返回具有给定`rel`的链接 |
| `List<Link> getLinks()` | 这将返回此资源中包含的所有链接 |
| `boolean hasLink(String rel)` | 这将返回资源是否包含具有给定`rel`的链接 |
| `boolean hasLinks()` | 这将返回资源是否包含任何链接 |
| `boolean removeLinks()` | 这将删除到目前为止添加到资源中的所有链接 |
| `Boolean equals(Object obj)` |   |
| `int hashCode()` |   |
| `String toString()` |   |

两个方便的构造函数，一个用于获取内容的 getter，以及所有与链接相关的辅助函数，这就是 Resource 类的组成部分。

### 可识别的接口

`Identifiable`接口在 Spring HATEOAS 中扮演着重要角色，因为关键类`Resource`、`ResourceSupport`、`Resources`和`PagedResources`类，我们稍后将介绍的这些类都是`Identifiable`的实现。稍后我们将介绍所有这些关键类。

`Identifiable`接口是 Spring HATEOAS 的一个单方法接口（通用接口），用于在对象中定义`Id`：

```java
public interface Identifiable<ID extends Serializable> {
  ID getId();
}
```

因此，框架使用这种方法来检索 ID，对传入对象的性质几乎没有要求。由于一个类可以实现多个接口的能力，向对象添加这样的限定符是没有成本的。此外，这个接口的契约是最小的。

框架对这个接口（和方法）最重要的用途是从`Resource`对象构建链接。看一下`LinkBuilderSupport`的`slash`方法。您会注意到，如果`ID`不是`Identifiable`的实例（这通常是最终结果），则`Link`将附加到`ID`类型的`toString()`表示。

### 提示

如果您考虑实现自定义 ID 类型，请记住这种行为。

### 抽象化实体的@Id

如果您计划坚持使用 Spring HATEOAS 而不将其扩展到 Spring Data REST，那么将基本实体与它们的`@Id`解耦可能并不是绝对必要的。至少不是我们所做的方式。

这种做法来自 Oliver Gierke，在他的`Spring RestBucks`应用程序中。Spring RestBucks 是一个展示现代 Spring REST 功能的示例应用程序。

### 注意

Oliver Gierke 是 Pivotal Software, Inc.的 Spring Data 首席开发人员。他还参与了 Spring HATEOAS。Spring Data 是一个令人惊叹的项目和产品。我们可以信任 Oliver Gierke 的愿景和决定。

在他的`AsbtractId`实现中，O. Gierke 将`Id`属性定义为私有，并将其注释为`@JsonIgnore`。他引导我们不将`Id`属性作为资源内容的一部分暴露出来。在 REST 中，资源的 ID 应该是其 URI。

如果您有机会查看 Spring Data REST，这种方法完全符合框架的一部分，它将 REST 资源与 Spring Data 存储库强烈相关联。

我们选择不在本书的范围内涵盖 Spring Data REST。然而，不暴露实体 ID 对我们的应用程序并不是关键的。出于这些原因，也因为我们希望在这一点上保持与第七章“开发 CRUD 操作和验证”一致，ID 将作为资源属性公开。

## 还有更多...

如果我们的 HATEOAS 介绍还不够清晰，无法让您了解原则，请阅读 Pivotal（[Spring.io](http://Spring.io)）的这个演示：

[`spring.io/understanding/HATEOAS`](https://spring.io/understanding/HATEOAS)

## 另请参阅

+   我们建议您访问 O. Gierke 的 Spring REST 展示应用，该应用展示了 Spring HATEOAS 的实践，无论是否与 Spring Data REST 配合使用，网址为[`github.com/olivergierke/spring-restbucks`](https://github.com/olivergierke/spring-restbucks)。

+   您可以在[`github.com/spring-projects/spring-hateoas/issues/66`](https://github.com/spring-projects/spring-hateoas/issues/66)找到一些关于 ID 暴露的讨论。

+   我们建议您阅读更多关于 Spring Data REST 的内容，因为我们只是介绍了一点点。Spring Data REST 在 Spring Data 存储库的基础上构建 REST 资源，并自动发布它们的 CRUD 服务。您可以在[`docs.spring.io/spring-data/rest/docs/current/reference/html`](http://docs.spring.io/spring-data/rest/docs/current/reference/html)了解更多信息。

# 为超媒体驱动的 API 构建链接

在这个示例中，我们将重点介绍如何使用 Spring HATEOAS 创建链接以及如何将它们绑定到资源上。

我们将详细介绍资源装配器，这些是可重用的过渡组件，用于从实体（如`Index`）到它们的资源（`IndexResource`）的转换。这些组件还提供了链接创建的支持。

## 如何做…

1.  创建的资源（IndexResource，ChartResource，ExchangeResource，IndustryResource，MarketResource 等）是从它们关联的实体（Index，ChartIndex，ChartStock，Exchange，Industry，Market 等）使用资源装配器注册为`@Component`创建的：

```java
import static org.sfw.hateoas.mvc.ControllerLinkBuilder.linkTo;
import static org.sfw.hateoas.mvc.ControllerLinkBuilder.methodOn;
import org.sfw.hateoas.mvc.ResourceAssemblerSupport;
import org.sfw.hateoas.EntityLinks;
import static edu.zc.csm.api.resources.ChartResource.CHART;
import static edu.zc.csm.api.resources.ExchangeResource.EXCHANGE;
import static edu.zc.csm.api.resources.StockProductResource.COMPONENTS;

@Component
public class IndexResourceAssembler extends ResourceAssemblerSupport<Index, IndexResource> {
  @Autowired
  private EntityLinks entityLinks;
  public IndexResourceAssembler() {
    super(IndexController.class, IndexResource.class);
  }
  @Override
  public IndexResource toResource(Index index) {
    IndexResource resource = createResourceWithId(index.getId(), index);
    resource.add(
      entityLinks.linkToSingleResource(index.getExchange ()).withRel(EXCHANGE)
);
  resource.add(
  linkTo(methodOn(ChartIndexController.class).get(in dex.getId(), ".png", null, null, null, null, null, 	null, null)).withRel(CHART)
);
  resource.add(
    linkTo(methodOn(StockProductController.class).getS everal(null, null, index.getId(), null, null, 	null, null)).withRel(COMPONENTS)
);
return resource;
  }
  @Override
  protected IndexResource instantiateResource(Index entity) {
    return new IndexResource(entity);
  }
}
```

### 提示

我们使用这些装配器来生成资源的链接。它们使用`ControllerLinkBuilder`的静态方法（`linkTo`和`methodOn`）和在资源本身中定义为常量的显式标签（`EXCHANGE`，`CHART`和`COMPONENTS`）。

1.  我们已经修改了之前的 SwaggerConfig 类，使得这个类可以用于 Swagger 以外的其他领域的基于注解的配置。这个类已经改名为 AnnotationConfig。

1.  我们还在 AnnotationConfig 类中添加了以下两个注解：

```java
@EnableHypermediaSupport(type = { HypermediaType.HAL })

@EnableEntityLinks 
```

（因为这两个注解目前还没有 XML 等效项）。

1.  这些转换器中的所有目标控制器都已经在类级别上用@ExposesResourceFor 注解进行了注释。

1.  这些控制器现在也返回创建的资源或资源页面：

```java
@RestController
@ExposesResourceFor(Index.class)
@RequestMapping(value=INDICES_PATH, produces={"application/xml", "application/json"})
public class IndexController extends CloudstreetApiWCI<Index> {
  @Autowired
  private IndexService indexService;
  @Autowired
  private IndexResourceAssembler assembler;
  @RequestMapping(method=GET)
  public PagedResources<IndexResource> getSeveral(
    @RequestParam(value="exchange", required=false) String exchangeId,@RequestParam(value="market", required=false) MarketId marketId, @PageableDefault(size=10, page=0, sort={"previousClose"}, direction=Direction.DESC) Pageable pageable){
      return pagedAssembler.toResource( indexService.gather(exchangeId,marketId, pageable), assembler);
  }
  @RequestMapping(value="/{index:[a-zA-Z0-9^.-]+}{extension:\\.[a-z]+}", method=GET)
  public IndexResource get(
    @PathVariable(value="index") String indexId, @PathVariable(value="extension") String extension){
    return assembler.toResource( indexService.gather(indexId));
}
}
```

1.  在这里，我们使 CloudstreetApiWCI 成为通用的。这样，CloudstreetApiWCI 可以有一个通用的 PagedResourcesAssembler @Autowired：

```java
@Component
@PropertySource("classpath:application.properties")
public class CloudstreetApiWCI<T extends Identifiable<?>> 
  extends WebContentInterceptor {
...
    @Autowired
    protected PagedResourcesAssembler<T> pagedAssembler;
...
}
```

### 提示

由于`WebCommonInterceptor`类的传统目的不是作为一个超级控制器共享属性和实用方法，我们将在控制器和`WebCommonInterceptor`之间创建一个中间组件。

1.  为了@Autowire PagedResourcesAssemblers，就像我们做的那样，我们在 dispatcher-servlet.xml 中注册了一个 PagedResourcesAssembler bean：

```java
  <bean class="org.sfw.data.web.PagedResourcesAssembler">
    <constructor-arg><null/></constructor-arg>
    <constructor-arg><null/></constructor-arg>
  </bean>
```

1.  因此，现在调用^GDAXI 指数代码的 API（http://cloudstreetmarket.com/api/indices/%5EGDAXI.xml）会产生以下输出：![如何做…](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00883.jpeg)

### 提示

作为链接，我们表达了端点和 URI 路径。从这些链接中，我们可以检索与指数相关的其他实体（如果我们想要公开它们的话）。

## 工作原理…

本节具体详细介绍了链接的创建。

### 资源装配器

这种专门的转换器（资源装配器）是为了可重用性而设计的。它们的主要功能如下：

+   实例化资源并用内容进行填充

+   从实体状态或静态全局设计创建资源的链接

该框架提供了一个`ResourceAssemblerSupport`超类，其作用是减少装配器职责中的样板代码。

`ResourceAssemblerSupport`类是一个抽象的泛型类。它通过提供一些额外的方法来丰富组装器。以`T`作为控制器的类或超级类型，其签名如下：

```java
public abstract class ResourceAssemblerSupport<T, D extends ResourceSupport> implements ResourceAssembler<T, D>
```

这里的表格提供了`ResourceAssemblerSupport`的 JavaDoc 的一瞥：

| 方法 | 描述 |
| --- | --- |
| `List<D> toResources(Iterable<? extends T> entities)` | 这将所有给定的实体转换为资源 |
| `protected D createResourceWithId(Object id, T entity)` | 这将创建一个带有给定 ID 的自链接的新资源 |
| `D createResourceWithId(Object id, T entity, Object... parameters)` | - |
| `protected D instantiateResource(T entity)` | 这将实例化资源对象。默认实现将假定一个`no-arg`构造函数并使用反射。但是，如果需要，可以重写它以手动设置对象实例（例如，以改善性能） |

`ResourceAssemblerSupport`类还实现了`ResourceAssembler`，这是一个单方法接口，强制组装器提供`toResource(T entity)`方法：

```java
public interface ResourceAssembler<T, D extends ResourceSupport> {
  D toResource(T entity);
} 
```

可以注意到我们在组装器中重写了`instantiateResource`方法。如 JavaDoc 中所述，不重写它会导致框架通过反射实例化资源，寻找资源中的`no-arg`构造函数。

我们更倾向于避免在我们的资源中使用这样的构造器，因为它们可能会有点超负荷。

### PagedResourcesAssembler

这个令人惊奇的通用超级组装器用于为客户端构建基于链接的资源页面。通过极少量的配置，Spring HATEOAS 为我们构建了一个完整且开箱即用的、完全填充的类型资源页面。

根据我们呈现的配置，您可以尝试调用以下 URL：

[`cloudstreetmarket.com/api/indices.xml`](http://cloudstreetmarket.com/api/indices.xml)

通过这样做，您应该获得以下输出：

![PagedResourcesAssembler](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00884.jpeg)

你能看到**next rel**链接吗？它是如何通过反射从我们的方法处理程序注解及其默认和使用的值构建的？尝试跟随**next**链接，看看导航如何更新并平滑增加。

在`IndexController.getSeveral()`方法处理程序（如下面的代码片段所示）中，我们确保每个单独的资源都通过使用我们自定义的`IndexResourceAssembler`来构建（内容和链接）：

```java
@RequestMapping(method=GET)
public PagedResources<IndexResource> getSeveral(
@RequestParam(value="exchange", required=false) String exchangeId,
@RequestParam(value="market", required=false) MarketId marketId,
@PageableDefault(size=10, page=0, sort={"previousClose"}, direction=Direction.DESC) Pageable pageable){
  return pagedAssembler.toResource(
  indexService.gather(exchangeId, marketId, pageable), 
  assembler);
}
```

### 构建链接

让我们看看我们在组装器中构建资源链接的方式。在`IndexResourceAssembler`中呈现的`toResource()`方法使用了两种不同的技术。

通过**EntityLinks**的第一种技术使用 JPA 实体；第二种技术通过`ControllerLinkBuilder`静态方法直接使用`Controllers`。

#### EntityLinks

通过在配置类中声明`@EnableEntityLinks`注解，会注册一个`EntityLinks`实现：`ControllerEntityLinks`。查找**ApplicationContext**的所有 Spring MVC 控制器，以寻找携带`@ExposesResourceFor(xxx.class)`注解的控制器。

Spring MVC 控制器上的`@ExposesResourceFor`注解公开了控制器管理的模型类型。这种注册使控制器和 JPA 实体之间的必要映射得以实现。

还必须注意，注册的`ControllerEntityLinks`实现假定控制器上有特定的`@RequestMapping`配置。`@RequestMapping`配置如下所示：

+   对于资源集合，期望有一个类级别的`@RequestMapping`注解。然后控制器必须暴露一个映射到空路径的方法处理程序，例如`@RequestMapping(method = RequestMethod.GET)`。

+   对于单个资源，这些资源使用所管理的 JPA 实体的`id`公开，例如`@RequestMapping("/{id}")`。

承认这些观点，`EntityLinks`实现（`ControllerEntityLinks`）从`@Autowiring`中使用以生成使用其提供的方法集的`Links`：

```java
public interface EntityLinks extends Plugin<Class<?>>{ 
  LinkBuilder linkFor(Class<?> type);
  LinkBuilder linkFor(Class<?> type, Object... parameters);
  LinkBuilder linkForSingleResource(Class<?> type, Object id);
  LinkBuilder linkForSingleResource(Identifiable<?> entity);
  Link linkToCollectionResource(Class<?> type);
  Link linkToSingleResource(Class<?> type, Object id);
  Link linkToSingleResource(Identifiable<?> entity);
}
```

#### ControllerLinkBuilder

正如介绍的那样，Spring HATEOAS 提供了`ControllerLinkBuilder`实用程序，它允许通过指向控制器类来创建链接：

```java
resource.add(
  linkTo(
  methodOn(StockProductController.class)
  .getSeveral(null, null, index.getId(), null, null, null, null)
  )
  .withRel(COMPONENTS)
);
```

如 Spring HATEOAS 参考中所指定的，`ControllerLinkBuilder`在底层使用 Spring 的`ServletUriComponentsBuilder`来从当前请求中获取基本 URI 信息。

如果我们的应用程序在`http://cloudstreetmarket/api`上运行，那么框架将在这个根 URI 的基础上构建`Links`，并将其附加到根控制器映射（`/indices`），然后再附加到后续方法处理程序特定的路径。

## 还有更多…

### 在@RequestMapping 中使用正则表达式

在`IndexController`、`StockProductController`、`ChartStockController`和`ChartIndexController`中，用于检索单个资源的`GET`方法处理程序具有特殊的`@RequestMapping`定义。

这是 IndexController 的`get()`方法：

```java
@RequestMapping(value="/{index:[a-zA-Z0-9^.-]+}{extension:\\.[a-z]+}", method=GET)
public IndexResource get(
  @PathVariable(value="index") String indexId, 
  @PathVariable(value="extension") String extension){
  return assembler.toResource(indexService.gather(indexId));
}
```

我们最终选择了这个选项，因为 Yahoo!的指数代码似乎比简单的字符串复杂一些。特别是考虑到这些代码可能携带一个或多个点。

这种情况导致 Spring MVC 无法正确区分`@PathVariable`索引和`extension`（在一半的情况下将它们剥离）。

幸运的是，Spring MVC 允许我们使用正则表达式定义 URI 模板模式。语法是`{varName:regex}`，其中第一部分定义变量名，第二部分定义正则表达式。

您将注意到我们为我们的指数定义的正则表达式：

`[a-zA-Z0-9^.-]+`表达式，特别允许`^`和`.`字符，在 Yahoo!的指数代码中通常使用。

## 另请参阅

+   要了解有关 Spring HATEOAS 的更多信息，请参考[`docs.spring.io/spring-hateoas/docs/current/reference/html/`](http://docs.spring.io/spring-hateoas/docs/current/reference/html/)。

+   介绍的 HATEOAS 表示实现了**Hypertext Application Language** (**HAL**)。 HAL 是 Spring HATEOAS 支持的默认渲染。在[`tools.ietf.org/html/draft-kelly-json-hal-06`](https://tools.ietf.org/html/draft-kelly-js)和[`stateless.co/hal_specification.html`](http://stateless.co/hal_specification.html)了解更多关于 HAL 规范的信息。

# 选择一种公开 JPA 实体的策略

在资源中公开的`content`对象是 JPA 实体。将 JPA 实体包装在资源中的有趣之处在于实体本身的低级性质，它据说代表了一个受限的可识别领域。这个定义理想情况下应该完全转换为公开的 REST 资源。

那么，我们如何在 REST HATEOAS 中表示一个实体？我们如何安全而统一地表示 JPA 关联？

这个示例提供了一种简单而保守的方法来回答这些问题。

## 如何做到这一点…

1.  我们介绍了一个用作资源的实体（`Index.java`）。这里还有另一个用到的实体：`Exchange.java`。这个实体提供了一种类似的策略来公开其 JPA 关联：

```java
import edu.zc.csm.core.converters.IdentifiableSerializer;
import edu.zc.csm.core.converters.IdentifiableToIdConverter;

@Entity
public class Exchange extends ProvidedId<String> {
  private String name;

  @ManyToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "market_id", nullable=true)
  @JsonSerialize(using=IdentifiableSerializer.class)
  @JsonProperty("marketId")
  @XStreamConverter(value=IdentifiableToIdConverter.class, strings={"id"})
  @XStreamAlias("marketId")
  private Market market;

  @OneToMany(mappedBy = "exchange", cascade = CascadeType.ALL, fetch=FetchType.LAZY)
  @JsonIgnore
  @XStreamOmitField
  private Set<Index> indices = new LinkedHashSet<>();

  @OneToMany(mappedBy = "exchange", cascade = CascadeType.ALL, fetch=FetchType.LAZY)
  @JsonIgnore
  @XStreamOmitField
  private Set<StockProduct> stocks = new LinkedHashSet<>();

  public Exchange(){}
  public Exchange(String exchange) {
    setId(exchange);
  }

  //getters & setters

  @Override
      public String toString() {
        return "Exchange [name=" + name + ", market=" + market + ", id=" + id+ "]";
      }
} 
```

1.  `Exchange.java`实体引用了两个自定义实用程序类，用于以特定的方式转换外部实体作为主实体渲染的一部分（JSON 或 XML）。这些实用程序类是`IdentifiableSerializer`和`IdentifiableToIdConverter`：

+   `IdentifiableSerializer`类用于 JSON marshalling：

```java
import org.springframework.hateoas.Identifiable;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
public class IdentifiableSerializer extends JsonSerializer<Identifiable<?>> {
   @Override
   public void serialize(Identifiable<?> value, JsonGenerator jgen, SerializerProvider provider) throws IOException, JsonProcessingException {
    provider.defaultSerializeValue(value.getId(), jgen);
   }
}
```

+   `IdentifiableToIdConverter`类用于 XML marshlling，并且构建了 XStream 依赖项：

```java
import com.thoughtworks.xstream.converters.Converter;
public class IdentifiableToIdConverter implements Converter {
    private final Class <Identifiable<?>> type;
    public IdentifiableToIdConverter(final Class <Identifiable<?>> type, final Mapper mapper, final ReflectionProvider reflectionProvider, final ConverterLookup lookup, final String valueFieldName) {
        this(type, mapper, reflectionProvider, lookup, valueFieldName, null);
    }
  public IdentifiableToIdConverter(final Class<Identifiable<?>> type, final Mapper mapper, final ReflectionProvider reflectionProvider, final ConverterLookup lookup, final String valueFieldName, Class valueDefinedIn) {
        this.type = type;
        Field field = null;
        try {
  field = (valueDefinedIn != null? valueDefinedIn : type.getSuperclass()).getDeclaredField("id");
  if (!field.isAccessible()) {
    field.setAccessible(true);
    }
      } catch (NoSuchFieldException e) {
        throw new IllegalArgumentException( 	e.getMessage()+": "+valueFieldName);
          }
      }
      public boolean canConvert(final Class type) {
        return type.isAssignableFrom(this.type);
    }
    public void marshal(final Object source, final HierarchicalStreamWriter writer,final 	MarshallingContext context) {
          if(source instanceof Identifiable){
            writer.setValue( ((Identifiable<?>)source).getId() .toString()
          );
        }
      }
    public Object unmarshal(final HierarchicalStreamReader reader, final UnmarshallingContext context) {
      return null;
    }
}
```

## 它是如何工作的…

让我们了解一下这个策略是如何工作的。

### REST CRUD 原则

REST 的一个架构约束是提供统一的接口。通过从可以从不同的 HTTP 方法（如果适用）针对的端点公开资源来实现统一的接口。

资源也可以以多种表示形式（`json`，`xml`等）公开，并且信息或错误消息必须是自描述的。 HATEOAS 的实现为 API 的自解释特性提供了巨大的奖励。

在 REST 中，越直观和可推断的事物越好。从这个角度来看，作为 Web/UI 开发人员，我应该能够假设以下内容：

+   我从端点的`GET`调用接收到的对象的结构将是我必须在`PUT`调用（对象的编辑）中发送回去的预期结构

+   类似地，相同的结构应该用于创建新对象（`POST`方法）

在不同的 HTTP 方法之间保持一致的有效负载结构是在捍卫 API 利益时使用的*SOLID*和保守的论点。*捍卫 API 利益几乎总是时候*。

### 暴露最少

在重构本章期间，暴露最少量的信息是核心思想。通常这是确保一个端点不会用于暴露初始控制器之外的信息数据的好方法。

JPA 实体可以与其他实体（`@OneToOne`，`@OneToMany`，`@ManyToOne`或`@ManyToMany`）关联。

其中一些关联已经用`@JsonIgnore`（和`@XStreamOmitField`）进行了注释，另一些关联已经用`@JsonSerialize`和`@JsonProperty`（和`@XStreamConverter`和`@XStreamAlias`）进行了注释。

#### 如果实体不拥有关系

在这种情况下，实体的数据库表没有指向目标第二实体表的外键。

这里的策略是完全忽略 REST 中的关系，以反映数据库状态。

`ignore`指令取决于支持的表示和选择的实现。

对于`json`，我们使用`Jackson`，解决方案是：`@JsonIgnore`。

对于`xml`，我们使用`XStream`，解决方案是：`@XstreamOmitField`。

#### 如果实体拥有关系

在这里，实体的数据库表具有指向目标第二实体表的外键。

如果我们计划更新此表的实体，该实体依赖于另一个表的实体，我们将不得不为该实体提供此外键。

然后的想法是将这个外键作为专用字段公开，就像数据库表的所有其他列一样。再次，实现此的解决方案取决于支持的表示和配置的编组器。

对于`json`和`Jackson`，我们使用以下代码片段完成了这一点：

```java
@JsonSerialize(using=IdentifiableSerializer.class)
@JsonProperty("marketId")
```

正如您所看到的，我们重命名属性以表明我们正在呈现（并期望）一个 ID。我们创建了`IdentifiableSerializer`类，从实体（从`Identifiable`接口）中提取`ID`，并将仅此`ID`放入属性的值中。

对于`xml`和`XStream`，它已经是：

```java
@XStreamConverter(value=IdentifiableToIdConverter.class, strings={"id"})
@XStreamAlias("marketId")
```

同样，我们重命名属性以表明我们正在呈现一个`ID`，并且我们针对自定义转换器`IdentifiableToIdConverter`，该转换器也仅选择实体的**ID**作为属性的值。

这是`xml`表示示例的`^AMBAPT`索引的示例：

![如果实体拥有关系](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00885.jpeg)

### 资源的分离

这种策略促进了资源之间的明确分离。每个资源的显示字段完全匹配数据库模式。这是 Web 开发中的标准做法，以保持不同 HTTP 方法的 HTTP 请求有效负载不变。

当采用 HATEOAS 时，我们应该充分鼓励使用链接来访问相关实体，而不是嵌套视图。

以前的配方*为超媒体驱动的 API 构建链接*提供了使用链接访问（使用链接）与`@...ToOne`和`@...ToMany`相关联的实体的示例。以下是在先前的配方中实现的公开实体中的这些链接的示例：

![资源的分离](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00886.jpeg)

## 还有更多…

我们在这里详细介绍了实现的编组器的官方信息来源。

### Jackson 自定义序列化器

您可以在以下位置找到这些序列化器的官方 wiki 页面指南：

[`wiki.fasterxml.com/JacksonHowToCustomSerializers`](http://wiki.fasterxml.com/JacksonHowToCustomSerializers)

### XStream 转换器

XStream 已从[codehaus.org](http://codehaus.org)迁移到**Github**。要查看有关 XStream 转换器的官方教程，请转到：

[`x-stream.github.io/converter-tutorial.html`](http://x-stream.github.io/converter-tutorial.html)

# 使用 OAuth 从第三方 API 检索数据

在使用 OAuth2 对用户进行身份验证后，了解如何使用用户的 OAuth2 帐户调用远程第三方 API 是很有用的。

## 如何做…

1.  您可能已经注意到`IndexController`，`StockProductController`，`ChartIndexController`和`ChartStockController`调用了名为`gather(…)`的底层服务方法。这个概念表明对第三方提供商（Yahoo!）的查找是进行的。

1.  例如，在`IndexServiceImpl`中，您可以找到`gather(String indexId)`方法：

```java
@Override
public Index gather(String indexId) {
    Index index = indexRepository.findOne(indexId);
    if(AuthenticationUtil.userHasRole(Role.ROLE_OAUTH2)){
      updateIndexAndQuotesFromYahoo(index != null ? Sets.newHashSet(index) : Sets.newHashSet(new Index(indexId)));
      return indexRepository.findOne(indexId);
    }
  return index;
}
```

1.  真正起到了服务层与第三方 API 之间的桥梁的是`updateIndexAndQuotesFromYahoo(…)`方法：

```java
  @Autowired
  private SocialUserService usersConnectionRepository;

  @Autowired
  private ConnectionRepository connectionRepository;

  private void updateIndexAndQuotesFromYahoo(Set<Index> askedContent) {
      Set<Index> recentlyUpdated = askedContent.stream()
      .filter(t -> t.getLastUpdate() != null && DateUtil.isRecent(t.getLastUpdate(), 1))
        .collect(Collectors.toSet());

    if(askedContent.size() != recentlyUpdated.size()){
      String guid = AuthenticationUtil.getPrincipal().getUsername();
    String token = usersConnectionRepository .getRegisteredSocialUser(guid) .getAccessToken();
    Connection<Yahoo2> connection = connectionRepository .getPrimaryConnection(Yahoo2.class);
    if (connection != null) {
      askedContent.removeAll(recentlyUpdated);
        List<String> updatableTickers = askedContent.stream()
         .map(Index::getId)
         .collect(Collectors.toList());
     List<YahooQuote> yahooQuotes = connection.getApi() .financialOperations().getYahooQuotes(updatableTickers, token);

     Set<Index> upToDateIndex = yahooQuotes.stream()
       .map(t -> yahooIndexConverter.convert(t))
       .collect(Collectors.toSet());

      final Map<String, Index> persistedStocks = indexRepository.save(upToDateIndex) 	.stream()
        .collect(Collectors.toMap(Index::getId, Function.identity()));

     yahooQuotes.stream()
      .map(sq -> new IndexQuote(sq, persistedStocks.get(sq.getId())))
        .collect(Collectors.toSet());
      indexQuoteRepository.save(updatableQuotes);
    }
  }
} 
```

1.  在 Facebook、Twitter 或 LinkedIn 的情况下，您应该能够找到一个完整的 API 适配器，以执行对其 API 的调用，而无需进行修改。在我们的情况下，我们不得不开发所需的适配器，以便从 Yahoo!中检索和利用财务数据。

1.  我们在`FinancialOperations`接口中添加了两个方法，如下所示：

```java
public interface FinancialOperations {
  List<YahooQuote> getYahooQuotes(List<String> tickers, String accessToken) ;
  byte[] getYahooChart(String indexId, ChartType type, ChartHistoSize histoSize, ChartHistoMovingAverage histoAverage, ChartHistoTimeSpan histoPeriod, Integer intradayWidth, Integer intradayHeight, String token);
}
```

1.  这个接口有一个`FinancialTemplate`实现，如下所示：

```java
public class FinancialTemplate extends AbstractYahooOperations implements FinancialOperations {
    private RestTemplate restTemplate;
  public FinancialTemplate(RestTemplate restTemplate, boolean isAuthorized, String guid) {
    super(isAuthorized, guid);
    this.restTemplate = restTemplate;
    this.restTemplate.getMessageConverters() add( new YahooQuoteMessageConverter( MediaType.APPLICATION_OCTET_STREAM));
    }
  @Override
  public List<YahooQuote> getYahooQuotes(List<String> tickers, String token)  {
      requiresAuthorization();
      final StringBuilder sbTickers = new StringBuilder();
      String url = "quotes.csv?s=";
      String strTickers = "";
      if(tickers.size() > 0){
        tickers.forEach(t -> strTickers = sbTickers.toString();
          strTickers = strTickers.substring(0, strTickers.length()-1);
      }
       HttpHeaders headers = new HttpHeaders();
       headers.set("Authorization", "Bearer "+token);
       HttpEntity<?> entity = new HttpEntity<>(headers);
       return restTemplate.exchange(buildUri(FINANCIAL, url.concat(strTickers).concat("&f=snopl1c1p2hgbavx	c4")), HttpMethod.GET, entity , QuoteWrapper.class).getBody();
  } 
  ...
}
```

1.  `FinancialTemplate`类作为全局`Yahoo2Template`的一部分进行初始化，并在`IndexServiceImpl`的`connection.getApi()`调用中返回。

1.  使用这种技术，不仅可以从 Yahoo!中检索指数和股票报价，还可以检索图表，现在我们能够显示来自 25000 多支股票和 30000 多个指数的实时数据。![如何做…](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00887.jpeg)

1.  客户端能够使用随每个结果元素一起提供的 HATEOAS 链接。它使用这些链接来呈现详细视图，如**指数详情**或**股票详情**（新屏幕）。![如何做…](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00888.jpeg)

## 它是如何工作的…

让我们了解这个配方背后的理论。

### 介绍 Yahoo!的财务数据

在我们的应用程序环境中，仍然有一个需要解释的重构。这是关于历史数据和图表的。

Yahoo!财务 API 提供了历史数据。这些数据可以用来构建图表，最初计划是这样做的。现在，Yahoo!也生成图表（用于历史和盘中数据），这些图表是相当可定制的（时间段、平均线、图表或股票的显示选项等）。

我们决定放弃历史部分，这在技术上与报价检索（数据快照）非常相似，专门使用由 Yahoo!生成的图表。

#### 图表生成/显示

我们的实现提供了一个有趣的 REST 图像服务示例。看看`ChartIndexController`（或`ChartStockController`）并看看图像如何以字节数组返回。

还要看一下`home_financial_graph.js`文件，了解接收到的内容是如何设置到 HTML `<img…>`标记中的。

### 财务数据是如何拉取/刷新的？

这里的想法是依赖于 OAuth 认证的用户。雅虎！为经过身份验证和未经身份验证的用户提供不同的费率和限制。雅虎！认为来自我们 IP 的调用太多，这将是一个问题。但是，如果有太多来自特定用户的调用，雅虎！将限制该用户，而不会影响应用程序的其余部分（应用程序可以进一步通过应用程序恢复）。

正如您所看到的，潜在处理雅虎！金融数据的方法处理程序通过名为`gather()`的方法调用适当的底层服务。

在这些`gather()`方法中，雅虎第三方 API 介入了我们的数据库和我们的控制器之间。

如果用户使用 OAuth2 进行了身份验证，则底层服务会检查数据是否存在于数据库中，以及是否已经更新到足够近的时间来匹配数据类型的预定义缓冲期（`indices`和`stocks`为一分钟）：

+   如果答案是肯定的，则将这些数据返回给客户端

+   如果答案是否定的，则从雅虎！请求预期的数据，转换，存储在数据库中，并返回给客户端

目前没有计划针对未经 OAuth 认证的用户，但我们可以想象很容易使用通用的雅虎！OAuth 账户来创建它们。

### 调用第三方服务

对于所呈现的配方，这部分是在`updateIndexAndQuotesFromYahoo`方法中完成的。我们的 Spring 配置定义了一个`connectionRepository` bean，为每个用户创建了一个`request`范围。`connectionRepository`实例是从我们的`SocialUserServiceImpl`的`createConnectionRepository`工厂方法创建的。

基于此，我们在服务层中`@Autowire`这两个 bean：

```java
@Autowired
private SocialUserService usersConnectionRepository;
@Autowired
private ConnectionRepository connectionRepository;
```

然后，`updateIndexAndQuotesFromYahoo`方法从 Spring Security 中获取已登录的`userId`（`guid`）：

```java
String guid = AuthenticationUtil.getPrincipal().getUsername();
```

访问令牌从`SocialUser`实体（来自数据库）中提取：

```java
String token = usersConnectionRepository .getRegisteredSocialUser(guid).getAccessToken();
```

从数据库中检索雅虎！连接：

```java
Connection<Yahoo2> connection = connectionRepository.getPrimaryConnection(Yahoo2.class);
```

如果连接不为空，则从连接对象调用第三方 API：

```java
List<YahooQuote> yahooQuotes = connection.getApi() .financialOperations().getYahooQuotes(updatableTickers, token);
```

再次，我们不得不开发实际的`FinancialTemplate`（雅虎！金融 API 的 Java 表示），但是您应该能够为您的第三方提供商找到这样的现有实现。

## 还有更多...

本节提供了许多现有的开源 Spring Social 适配器的列表，我们可以在我们的项目中使用

### Spring Social - 现有的 API 提供商

以下地址提供了连接支持和 API 绑定到许多热门服务提供商的 Spring 社交扩展的最新聚合：

[`github.com/spring-projects/spring-social/wiki/Api-Providers`](https://github.com/spring-projects/spring-social/wiki/Api-Providers)

## 另请参阅

+   **雅虎！金融股票代码**：我们已经在数据库中预先填充了一组对雅虎的金融引用（股票引用和指数引用），这使我们能够指向和搜索可以通过雅虎 API 第二次更新的资源。这组引用来自**Samir Khan**在他的博客[`investexcel.net/all-yahoo-finance-stock-tickers`](http://investexcel.net/all-yahoo-finance-stock-tickers)上发布的伟大工作。然后，我们使用基本文本编辑器和宏将这些 XLS 数据转换为 SQL。



# 第十四章：开发 CRUD 操作和验证

到目前为止，我们已经看到了如何构建 API 的只读 HTTP 方法。Spring MVC 控制器中的这些方法要求您掌握或至少了解一些技术的呈现。开发非只读的 HTTP 方法会引发一系列新的基础主题。每个主题都直接影响客户体验，因此每个主题都很重要。我们引入以下四个配方作为涵盖主题的框架：

+   将 REST 处理程序扩展到所有 HTTP 方法

+   使用 bean 验证支持验证资源

+   为 REST 国际化消息和内容

+   使用 HTML5 和 AngularJS 验证客户端表单

# 介绍

在这个阶段开发 CRUD 操作和验证结果是最广泛的主题之一。

我们的应用程序将在许多方面进行转变，从交易管理标准化到错误（和内容）的国际化，通过 REST 处理程序、HTTP 合规性。

与前几章和本书的全局策略一致，我们专注于 Spring MVC 在可伸缩性和微服务通信方面的最佳实践。决定跳过一些内容是一个艰难的选择，但框架不断适应新的设计和挑战。本书试图在现代、可持续和可伸缩的应用程序中呈现 Spring MVC 的一致集成。

这里介绍了四个配方。第一个配方将两个控制器转换为支持其各自资源的 CRUD 操作。这样做需要对数据库事务和 HTTP 规范进行审查。

本章介绍了 Spring MVC 支持的两种验证策略。由于验证错误通常需要以多种语言呈现，我们确保我们的应用程序支持国际化。我们简要介绍了 AngularJS 如何在这个视角中使用，以及如何用它来处理前端验证，这总是必要的，以将客户体验限制在业务特定数据管理的现实中。

# 将 REST 处理程序扩展到所有 HTTP 方法

这是本章的核心配方。我们将详细介绍如何使用 Spring MVC 方法处理程序处理我们尚未涵盖的 HTTP 方法：非只读方法。

## 准备就绪

我们将看到返回的状态代码和驱动`PUT`、`POST`和`DELETE`方法使用的 HTTP 标准。这将使我们配置符合 HTTP 规范的 Spring MVC 控制器。

我们还将审查请求负载映射注释，如`@RequestBody`是如何在幕后工作的，以及如何有效地使用它们。

最后，我们将打开 Spring 事务的窗口，因为这本身是一个广泛而重要的主题。

## 如何做…

以下步骤将介绍对两个控制器、一个服务和一个存储库所应用的更改：

1.  从 Eclipse 的**Git Perspective**中，检出分支`v7.x.x`的最新版本。然后，在`cloudstreetmarket-parent`模块上运行`maven clean install`（右键单击模块，转到**Run as…** | **Maven Clean**，然后再次转到**Run as…** | **Maven Install**），然后进行`Maven Update`项目以使 Eclipse 与 maven 配置同步（右键单击模块，然后转到**Maven** | **Update Project…**）。

1.  在`zipcloud-parent`和`cloudstreetmarket-parent`上运行`Maven clean`和`Maven install`命令。然后，转到**Maven** | **Update Project**。

1.  在本章中，我们专注于两个 REST 控制器：`UsersController`和新创建的`TransactionController`。

### 注意

`TransactionController`允许用户处理财务交易（从而购买或出售产品）。

1.  这里提供了`UserController`的简化版本：

```java
@RestController
@RequestMapping(value=USERS_PATH, produces={"application/xml", "application/json"})
public class UsersController extends CloudstreetApiWCI{
  @RequestMapping(method=POST)
  @ResponseStatus(HttpStatus.CREATED)
  public void create(@RequestBody User user, 
  @RequestHeader(value="Spi", required=false) String 	guid, @RequestHeader(value="OAuthProvider", required=false) String provider,
  HttpServletResponse response) throws IllegalAccessException{
  ...
  response.setHeader(LOCATION_HEADER, USERS_PATH + user.getId());
  }
  @RequestMapping(method=PUT)
  @ResponseStatus(HttpStatus.OK)
  public void update(@RequestBody User user, 
    BindingResult result){
    ...
  }
  @RequestMapping(method=GET)
  @ResponseStatus(HttpStatus.OK)
  public Page<UserDTO> getAll(@PageableDefault(size=10, page=0) Pageable pageable){
  return communityService.getAll(pageable);
  }
  @RequestMapping(value="/{username}", method=GET)
  @ResponseStatus(HttpStatus.OK)
  public UserDTO get(@PathVariable String username){
    return communityService.getUser(username);
  }
  @RequestMapping(value="/{username}", method=DELETE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void delete(@PathVariable String username){
    communityService.delete(username);
  }
}
```

1.  这里以简化版本呈现了**TransactionController**：

```java
@RestController
@ExposesResourceFor(Transaction.class)
@RequestMapping(value=ACTIONS_PATH + TRANSACTIONS_PATH, produces={"application/xml", "application/json"})
public class TransactionController extends CloudstreetApiWCI<Transaction> {
```

（这里提供的`GET`方法处理程序来自先前的配方。）

```java
  @RequestMapping(method=GET)
  @ResponseStatus(HttpStatus.OK)
  public PagedResources<TransactionResource> search(
    @RequestParam(value="user", required=false) String userName,
    @RequestParam(value="quote:[\\d]+", required=false) Long quoteId,
    @RequestParam(value="ticker:[a-zA-Z0-9-:]+", required=false) String ticker,
    @PageableDefault(size=10, page=0, sort={"lastUpdate"}, direction=Direction.DESC) Pageable pageable){
    Page<Transaction> page = transactionService.findBy(pageable, userName, quoteId, ticker);
      return pagedAssembler.toResource(page, assembler);
  }
  @RequestMapping(value="/{id}", method=GET)
  @ResponseStatus(HttpStatus.OK)
public TransactionResource get(@PathVariable(value="id") Long transactionId){
  return assembler.toResource(
    transactionService.get(transactionId));
  }
```

（这里介绍的`PUT`和`DELETE`方法处理程序是非只读方法。）

```java
  @RequestMapping(method=POST)
  @ResponseStatus(HttpStatus.CREATED)
public TransactionResource post(@RequestBody Transaction transaction) {
    transactionService.hydrate(transaction);
    ...
  TransactionResource resource = assembler.toResource(transaction);
  response.setHeader(LOCATION_HEADER, resource.getLink("self").getHref());
    return resource;
  }
  @PreAuthorize("hasRole('ADMIN')")
  @RequestMapping(value="/{id}", method=DELETE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
public void delete(@PathVariable(value="id") Long transactionId){
    transactionService.delete(transactionId);
  }
}
```

1.  在`post`方法中调用`hydrate`方法，为底层服务使用准备实体。它从请求有效负载中接收的 ID 填充了它的关系。

### 注意

这种技术将应用于用于 CRUD 的所有 REST 资源。

1.  这里是`transactionServiceImpl`中`hydrate`方法的详细信息：

```java
@Override
public Transaction hydrate(final Transaction transaction) {

  if(transaction.getQuote().getId() != null){
    transaction.setQuote(
      stockQuoteRepository.findOne(
        transaction.getQuote().getId()));
  }
  if(transaction.getUser().getId() != null){
   transaction.setUser(userRepository.findOne(transaction.getUser().getId()));
  }
  if(transaction.getDate() == null){
    transaction.setDate(new Date());
  }
  return transaction;
}
```

### 注意

这里没有什么惊人的；主要是为了构建我们的实体以满足我们的需求。可以创建一个接口来标准化这种做法。

1.  所有服务层都经过审查，以驱动统一的数据库事务。

1.  服务实现现在默认使用`@Transactional(readOnly = true)`进行注释。检查以下`TransactionServiceImpl`示例：

```java
@Service
@Transactional(readOnly = true)
public class TransactionServiceImpl implements TransactionService{
  ...
}
```

1.  这些服务实现的非只读方法使用`@Transactional`注解覆盖了类定义：

```java
  @Override
  @Transactional
  public Transaction create(Transaction transaction) {
  if(!transactionRepository.findByUserAndQuote(transaction.getUser(), transaction.getQuote()).isEmpty()){
      throw new DataIntegrityViolationException("A transaction for the quote and the user already exists!");
    }
    return transactionRepository.save(transaction);
  }
```

1.  这个原则也适用于自定义存储库实现（如`IndexRepositoryImpl`）：

```java
@Repository
@Transactional(readOnly = true)
public class IndexRepositoryImpl implements IndexRepository{
  @PersistenceContext 
  private EntityManager em;

  @Autowired
  private IndexRepositoryJpa repo;
  ...
  @Override
  @Transactional
  public Index save(Index index) {
    return repo.save(index);
  }
  ...
}
```

## 工作原理...

首先，让我们快速回顾一下本文中控制器中介绍的不同 CRUD 服务。以下表格对它们进行了总结：

| URI | 方法 | 目的 | 正常响应代码 |
| --- | --- | --- | --- |
| `/actions/transactions` | GET | 搜索交易 | 200 OK |
| `/actions/transactions/{id}` | GET | 获取交易 | 200 OK |
| `/actions/transactions` | POST | 创建交易 | 201 Created |
| `/actions/transactions/{id}` | DELETE | 删除交易 | 204 No Content |
| `/users/login` | POST | 登录用户 | 200 OK |
| `/users` | GET | 获取所有 | 200 OK |
| `/users/{username}` | GET | 获取用户 | 200 OK |
| `/users` | POST | 创建用户 | 201 Created |
| `/users/{username}` | PUT | 更新用户 | 200 OK |
| `/users/{username}` | DELETE | 删除用户 | 204 No Content |

### HTTP/1.1 规范 - RFC 7231 语义和内容

要理解本文中所做的一些决定（并合理化它们），我们必须对 HTTP 规范的一些要点进行一些解释。

在开始之前，可以随意访问与语义和内容相关的**HTTP 1/1**的互联网标准跟踪文档（RFC 7231）：

[`tools.ietf.org/html/rfc7231`](https://tools.ietf.org/html/rfc7231)

#### 基本要求

在 HTTP 规范文档中，请求方法概述（第 4.1 节）规定服务器必须支持`GET`和`HEAD`方法。所有其他请求方法都是可选的。

同一节还指定，使用已识别的方法名（`GET`、`POST`、`PUT`、`DELETE`等）进行的请求，但不匹配任何方法处理程序的请求应该以`405 Not supported`状态代码进行响应。同样，使用未识别的方法名（非标准）进行的请求应该以`501 Not implemented`状态代码进行响应。这两个语句都受 Spring MVC 的本地支持和自动配置。

#### 安全和幂等方法

该文档介绍了可以用来描述请求方法的安全和幂等限定符。安全方法基本上是只读方法。使用这种方法的客户端不会显式请求状态更改，并且不能期望请求的结果会导致状态更改。

正如“安全”一词所暗示的那样，这样的方法可以信任不会对系统造成任何伤害。

一个重要的元素是我们正在考虑客户端的观点。安全方法的概念不会阻止系统实施“潜在”有害的操作或过程，这些操作或过程实际上并非只读。无论发生什么，客户端都不会对此负责。在所有 HTTP 方法中，只有`GET`、`HEAD`、`OPTIONS`和`TRACE`方法被定义为安全方法。

规范使用幂等限定符来识别 HTTP 请求，当完全重复时，总是产生与第一个请求相同的后果。这里必须考虑客户端的观点。

幂等的 HTTP 方法是`GET`，`HEAD`，`OPTIONS`，`TRACE`（安全方法），以及`PUT`和`DELETE`。

方法的幂等性保证客户端，例如，即使在接收到任何响应之前发生连接问题，发送**PUT**请求也可以重复。

### 注意

客户端知道重复请求将产生相同的预期效果，即使原始请求成功，响应可能会有所不同。

#### 其他特定于方法的约束

`POST`方法通常与在服务器上创建资源相关联。因此，该方法应返回`201（已创建）`状态码，并提供一个标识符来创建资源的位置头字段。

然而，如果没有创建资源，`POST`方法（实际上）可能返回除`206（部分内容）`，`304（未修改）`和`416（范围不可满足）`之外的所有类型的状态码。

`POST`的结果有时可能是现有资源的表示。在这种情况下，例如，客户端可以通过`303`状态码和`Location`头字段重定向到该资源。作为`POST`方法的替代，`PUT`方法通常被选择来更新或更改现有资源的状态，并向客户端发送`200（OK）`或`204（无内容）`。

不一致匹配的边缘情况会引发`409（冲突）`或`415（不支持的媒体类型）`错误。

更新时找不到匹配项的边缘情况应该引发使用`201（已创建）`状态码创建资源。

另一组约束适用于成功接收的`DELETE`请求。这些请求应返回`204（无内容）`状态码，或者如果删除已经被处理，则返回`200（OK）`。如果没有，则状态码应为`202（已接受）`。

### 使用@RequestBody 映射请求有效载荷

在第四章中，*为无状态架构构建 REST API*，我们介绍了`RequestMappingHandlerAdapter`。我们已经看到 Spring MVC 委托给这个 bean 来提供对`@RequestMapping`注解的扩展支持。

从这个角度来看，`RequestMappingHandlerAdapter`是访问和重写`HttpMessageConverters`的中心组件，通过`getMessageConverters()`和`setMessageConverters(List<HttpMessageConverter<?>> messageConverters)`。

`@RequestBody`注解的作用与`HttpMessageConverters`紧密耦合。我们现在将介绍`HttpMessageConverters`。

### HttpMessageConverters

`HttpMessageConverters`，自定义或本机，绑定到特定的 MIME 类型。它们在以下情况下使用：

+   将 Java 对象转换为 HTTP 响应有效载荷。从`Accept`请求头 MIME 类型中选择，它们为`@ResponseBody`注解的目的提供服务（间接地为抽象`@ResponseBody`注解的`@RestController`注解提供服务）。

+   将 HTTP 请求有效载荷转换为 Java 对象。从`Content-Type`请求头 MIME 类型中选择，这些转换器在方法处理程序参数上存在`@RequestBody`注解时被调用。

更一般地说，`HttpMessageConverters`匹配以下`HttpMessageConverter`接口：

```java
public interface HttpMessageConverter<T> {
  boolean canRead(Class<?> clazz, MediaType mediaType);
  boolean canWrite(Class<?> clazz, MediaType mediaType);
  List<MediaType> getSupportedMediaTypes();
  T read(Class<? extends T> clazz, HttpInputMessage inputMessage) throws IOException, HttpMessageNotReadableException;
  void write(T t, MediaType contentType, HttpOutputMessage outputMessage) throws IOException, HttpMessageNotWritableException;
}
```

`getSupportedMediaTypes()`方法返回特定转换器支持的`mediaTypes`（MIME 类型）列表。这个方法主要用于报告目的和`canRead`和`canWrite`实现。这些`canRead`和`canWrite`资格方法由框架在运行时使用，首先选择`HttpMessageConverter`，它要么：

+   匹配客户端提供的`Content-Type`请求头，针对`@RequestBody`指定的 Java 类。

+   匹配客户端提供的`Accept`请求头，以便 HTTP 响应有效载荷对应于`@ResponseBody`指定的 Java 类（`@ResponseBody`指定的类型）。

#### 提供了 HttpMessageConverters

| 在最新版本的 Spring MVC（4+）中，一些额外的`HttpMessageConverters`与框架一起自然而然地出现。我们认为总结它们会有所帮助。以下表格表示了所有本地的`HttpMessageConverters`，mime 类型以及它们可以关联的 Java 类型。大部分来自 JavaDoc 的简短描述更多地揭示了它们的特点。 |

| URI | 支持的媒体类型（默认） | 转换为/从 |
| --- | --- | --- |
| `FormHttpMessage Converter` | 可以读/写 application/x-www-form-urlencoded，可以读取 multipart/form-data。 | `MultiValueMap<String, ?>` |
| 对于部分转换，默认还嵌入了`ByteArrayHttpMessageConverter`、`StringHttpMessageConverter`和`ResourceHttpMessageConverter`。 |
| `AllEncompassing FormHttpMessage Converter` | 可以读/写 application/x-www-form-urlencoded，可以读取 multipart/form-data。 | `MultiValueMap<String, ?>` |
| 这个转换器扩展了`FormHttpMessageConverter`，通过在类路径上找到 XML/JSON-based 部分的 JAXB 或 Jackson 来嵌入额外的`HttpMessageConverters`。 |
| `XmlAwareFormHttp MessageConverter` | 可以读/写 application/x-www-form-urlencoded，可以读取 multipart/form-data。 | `MultiValueMap<String, ?>` |
| 这个转换器扩展了`FormHttpMessageConverter`，通过`SourceHttpMessageConverter`添加了对基于 XML 的部分的支持。 |
| `BufferedImageHttp MessageConverter` | 可以读取所有已注册的图像阅读器支持的媒体类型。可以写入第一个可用的已注册图像写入器的媒体类型。 | `java.awt.image.BufferedImage` |
| `ByteArrayHttp MessageConverter` | 可以读取*/*，可以写入 application/octet-stream。 | `byte[]` |
| `GsonHttpMessage Converter` | 可以读/写 application/json, application/*+json。 | `java.lang.Object` |
| 使用 Google Gson 库的`Gson`类。这个转换器可以用来绑定带有类型的 bean 或无类型的 HashMap。 |
| `Jaxb2Collection HttpMessage Converter` | 可以读取 XML 集合。 | `T extends java.util.Collection` |
| 这个转换器可以读取包含带有`XmlRootElement`和`XmlType`注释的类的集合。请注意，这个转换器不支持写入。（JAXB2 必须存在于类路径上。） |
| `Jaxb2RootElement HttpMessage Converter` | 可以读/写 XML | `java.lang.Object` |
| 这个转换器可以读取带有`XmlRootElement`和`XmlType`注释的类，并写入带有`XmlRootElement`或其子类注释的类。（JAXB2 必须存在于类路径上。） |
| `MappingJackson2 HttpMessage Converter` | 可以读/写 application/json, application/*+json。 | `java.lang.Object` |
| 使用 Jackson 2.x ObjectMapper。这个转换器可以用来绑定带有类型的 bean 或无类型的 HashMap 实例。（Jackson 2 必须存在于类路径上。） |
| `MappingJackson2 XmlHttpMessage Converter` | 可以读/写 application/xml, text/xml, application/*+xml。 | `java.lang.Object` |
| 这使用了 Jackson 2.x 扩展组件来读取和写入 XML 编码的数据（[`github.com/FasterXML/jackson-dataformat-xml`](https://github.com/FasterXML/jackson-dataformat-xml)）。（Jackson 2 必须存在于类路径上。） |
| `MarshallingHttp MessageConverter` | 可以读/写 text/xml application/xml。 | `java.lang.Object` |
| 这使用了 Spring 的 Marshaller 和 Unmarshaller 抽象（OXM）。 |
| `ObjectToStringHttp MessageConverter` | 可以读/写 text/plain。 | `java.lang.Object` |
| 这使用`StringHttpMessageConverter`来读取和写入内容，并使用`ConversionService`来将字符串内容转换为目标对象类型和从目标对象类型转换为字符串内容。（必须进行配置。） |
| `ProtobufHttp MessageConverter` | 可以读取 application/json, application/xml, text/plain 和 application/x-protobuf。可以写入 application/json, application/xml, text/plain 和 application/x-protobuf, text/html。 | `javax.mail.Message` |
| 使用 Google 协议缓冲区（[`developers.google.com/protocol-buffers`](https://developers.google.com/protocol-buffers)）生成消息 Java 类，您需要安装`protoc`二进制文件。 |
| `ResourceHttp MessageConverter` | 可以读取/写入*/*。 | `org.springframework.core.io.Resource` |
| 如果可用，**Java 激活框架**（**JAF**）用于确定写入资源的内容类型。如果 JAF 不可用，则使用 application/octet-stream。 |
| `RssChannelHttp MessageConverter` | 可以读取/写入 application/rss+xml。 | `com.rometools.rome.feed.rss.Channel` |
| 此转换器可以处理来自 ROME 项目（[`github.com/rometools`](https://github.com/rometools)）的 Channel 对象。（ROME 必须存在于类路径上。） |
| `AtomFeedHttp MessageConverter` | 可以读取/写入 application/atom+xml。 | `com.rometools.rome.feed.atom.Feed` |
| 这可以处理来自 ROME 项目（[`github.com/rometools`](https://github.com/rometools)）的 Atom feeds。（ROME 必须存在于类路径上。） |
| `SourceHttpMessageConverter` | 可以读取/写入 text/xml，application/xml，application/*-xml。 | `javax.xml.transform.Source` |
| `StringHttpMessageConverter` | 可以读取/写入*/*。 | `java.lang.String` |

#### 使用 MappingJackson2HttpMessageConverter

在这个示例中，`MappingJackson2HttpMessageConverter`被广泛使用。我们将此转换器用于财务交易创建/更新方面和用户首选项更新方面。

或者，我们使用 AngularJS 将 HTML 表单映射到构建的 json 对象，其属性与我们的实体匹配。通过这种方式，我们将`json`对象作为`application/json`媒体类型进行`POST`/`PUT`。

之所以选择这种方法而不是发布`application/x-www-form-urlencoded`表单内容，是因为我们实际上可以将对象映射到实体。在我们的情况下，表单与后端资源完全匹配。这是 REST 设计的一个有益结果（和约束）。

### 使用@RequestPart 上传图像

`@RequestPart`注解可用于将`multipart/form-data`请求的一部分与方法参数关联起来。它可以与参数类型一起使用，例如`org.springframework.web.multipart.MultipartFile`和`javax.servlet.http.Part`。

对于任何其他参数类型，部分内容都会像`@RequestBody`一样通过`HttpMessageConverter`传递。

`@RequestBody`注解已被实现以处理用户个人资料图片。以下是我们从`UserImageController`的示例实现：

```java
    @RequestMapping(method=POST, produces={"application/json"})
    @ResponseStatus(HttpStatus.CREATED)
    public String save( @RequestPart("file") MultipartFile file, HttpServletResponse response){
    String extension = ImageUtil.getExtension(file.getOriginalFilename());
    String name = UUID.randomUUID().toString().concat(".").concat(extension);
    if (!file.isEmpty()) {
       try {
                byte[] bytes = file.getBytes();
                Path newPath = Paths.get(pathToUserPictures);
                Files.write(newPath, bytes, 	StandardOpenOption.CREATE);
       ...
  ...
  response.addHeader(LOCATION_HEADER, env.getProperty("pictures.user.endpoint").concat(name));
  return "Success";
  ...
  }
```

请求的文件部分被注入为参数。从请求文件的内容在服务器文件系统上创建一个新文件。响应中添加了一个新的`Location`头，其中包含指向创建的图像的链接。

在客户端上，此标头被读取并注入为我们 div 的`background-image` CSS 属性（请参见`user-account.html`）。

### 事务管理

该示例突出了我们在处理 REST 架构不同层之间的事务时应用的基本原则。事务管理本身是一个完整的章节，我们在这里只能呈现概述。

#### 简单的方法

在构建事务管理时，我们牢记 Spring MVC 控制器不是事务性的。在这种情况下，我们不能期望在控制器的同一方法处理程序中通过两个不同的服务调用进行事务管理。每个服务调用都会启动一个新的事务，并且预期该事务在返回结果时终止。

我们将服务定义为`@Transactional(readonly="true")`在类型级别，然后需要写访问权限的方法会在方法级别覆盖此定义，添加额外的`@Transactional`注解。我们的示例的第十步介绍了`TransactionServiceImpl`服务上的事务更改。使用默认传播，事务在事务性服务、存储库或方法之间得到维护和重用。

默认情况下，抽象的 Spring Data JPA 存储库是事务性的。我们只需要为我们的自定义存储库指定事务行为，就像我们为我们的服务所做的那样。

我们的配方的*第十一步*显示了对自定义存储库`IndexRepositoryImpl`进行的事务更改。

## 还有更多…

如前所述，我们在应用程序的不同层上配置了一致的事务管理。

### 事务管理

我们的覆盖范围有限，如果您对以下主题不熟悉，我们建议您寻找外部信息。

#### ACID 属性

有四个属性/概念经常用于评估事务的可靠性。因此，在设计事务时将它们牢记在心是有用且重要的。这些属性是原子性，一致性，隔离性和持久性。在维基百科页面上了解更多关于 ACID 事务的信息：

[`en.wikipedia.org/wiki/ACID`](https://en.wikipedia.org/wiki/ACID)

#### 全局与本地事务

我们只在应用程序中定义了本地事务。本地事务是在应用程序级别管理的，不能在多个 Tomcat 服务器之间传播。此外，当涉及多个事务资源类型时，本地事务无法确保一致性。例如，在与消息相关的数据库操作的用例中，当我们回滚无法传递的消息时，我们可能还需要回滚之前发生的相关数据库操作。只有实现了两阶段提交的全局事务才能承担这种责任。全局事务由 JTA 事务管理器实现处理。

在这个 Spring 参考文档中了解更多关于这个差异：

[`docs.spring.io/spring/docs/2.0.8/reference/transaction.html`](http://docs.spring.io/spring/docs/2.0.8/reference/transaction.html)

从历史上看，JTA 事务管理器是由 J2EE/JEE 容器专门提供的。现在，我们有其他选择，如 Atomikos ([`www.atomikos.com`](http://www.atomikos.com))，Bitronix ([`github.com/bitronix/btm`](https://github.com/bitronix/btm))或 JOTM ([`jotm.ow2.org/xwiki/bin/view/Main/WebHome`](http://jotm.ow2.org/xwiki/bin/view/Main/WebHome))等应用级 JTA 事务管理器实现，以确保 J2SE 环境中的全局事务。

Tomcat（7+）也可以与应用级 JTA 事务管理器实现一起工作，以反映容器中的事务管理，使用`TransactionSynchronizationRegistry`和 JNDI 数据源。

[`codepitbull.wordpress.com/2011/07/08/tomcat-7-with-full-jta`](https://codepitbull.wordpress.com/2011/07/08/tomcat-7-with-full-jta)

## 另请参阅

这三个标头可以从中获得性能和有用的元数据优势，这些在配方中没有详细说明。

+   **Cache-Control，ETag 和 Last-Modified**：Spring MVC 支持这些标头，作为入口点，我们建议您查看 Spring 参考：[`docs.spring.io/spring-framework/docs/current/spring-framework-reference/html/mvc.html#mvc-caching-etag-lastmodified`](http://docs.spring.io/spring-framework/docs/current/spring-framework-reference/html/mvc.html#mvc-caching-etag-lastmodified)

# 使用 bean 验证支持来验证资源

在介绍请求有效负载数据绑定过程之后，我们必须谈论验证。

## 准备工作

这个配方的目标是展示如何让 Spring MVC 拒绝不满足 bean 验证（JSR-303）或不满足定义的 Spring 验证器实现约束的请求体有效负载。

在 Maven 和 Spring 配置之后，我们将看到如何将验证器绑定到传入请求，如何定义验证器执行自定义规则，如何设置 JSR-303 验证，以及如何处理验证结果。

## 如何做…

1.  我们添加了一个 Maven 依赖项到 hibernate 验证器：

```java
<dependency>
  <groupId>org.hibernate</groupId>
  <artifactId>hibernate-validator</artifactId>
  <version>4.3.1.Final</version>
</dependency>
```

1.  在我们的`dispatcher-servlet.xml`（`cloudstreetmarket-api`）中注册了一个`LocalValidatorFactoryBean`：

```java
<bean id="validator" class="org.sfw.validation.beanvalidation.LocalValidatorFactoryBean"/>
```

1.  `UsersController`和`TransactionController`的`POST`和`PUT`方法签名已经改变，增加了`@Valid`注释在`@RequestBody`参数上：

```java
  @RequestMapping(method=PUT)
  @ResponseStatus(HttpStatus.OK)
  public void update(@Valid @RequestBody User user, 
  BindingResult result){
    ValidatorUtil.raiseFirstError(result);
    user = communityService.updateUser(user);
  }
```

### 注意

注意这里作为方法参数注入的`BindingResult`对象。我们将在大约一分钟内介绍`ValidatorUtil`类。

1.  我们的两个 CRUD 控制器现在有了一个新的`@InitBinder`注释的方法：

```java
  @InitBinder
    protected void initBinder(WebDataBinder binder) {
        binder.setValidator(new UserValidator());
    }
```

1.  这个方法将一个创建的验证器实现的实例绑定到请求。查看创建的`UserValidator`，它是`Validator`的实现：

```java
package edu.zipcloud.cloudstreetmarket.core.validators;
import java.util.Map;
import javax.validation.groups.Default;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;
import edu.zc.csm.core.entities.User;
import edu.zc.csm.core.util.ValidatorUtil;
public class UserValidator implements Validator {
  @Override
  public boolean supports(Class<?> clazz) {
    return User.class.isAssignableFrom(clazz);
  }
  @Override
  public void validate(Object target, Errors err) {
    Map<String, String> fieldValidation = ValidatorUtil.validate((User)target, Default.class);
    fieldValidation.forEach(
      (k, v) -> err.rejectValue(k, v)
    );
  }
}
```

1.  在`User`实体中，添加了一些特殊的注释：

```java
@Entity
@Table(name="users")
public class User extends ProvidedId<String> implements UserDetails{
  ...
  private String fullName;
  @NotNull
  @Size(min=4, max=30)
  private String email;
  @NotNull
  private String password;
  private boolean enabled = true;
  @NotNull
  @Enumerated(EnumType.STRING)
  private SupportedLanguage language;
  private String profileImg;

  @Column(name="not_expired")
  private boolean accountNonExpired;
  @Column(name="not_locked")
  private boolean accountNonLocked;

  @NotNull
  @Enumerated(EnumType.STRING)
  private SupportedCurrency currency;

  private BigDecimal balance;
  ...
}
```

1.  我们创建了`ValidatorUtil`类，以使这些验证更容易，并减少样板代码的数量：

```java
package edu.zipcloud.cloudstreetmarket.core.util;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;
import javax.validation.groups.Default;
import org.springframework.validation.BindingResult;

public class ValidatorUtil {
    private static Validator validator;
    static {
      ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
      validator = factory.getValidator();
    }
```

以下的`validate`方法允许我们从任何可能需要的位置调用 JSR 验证：

```java
public static <T> Map<String, String> validate(T object, Class<?>... groups) {
  Class<?>[] args = Arrays.copyOf(groups, groups.length + 1);
  args[groups.length] = Default.class;
  return extractViolations(validator.validate(object, args));
}
private static <T> Map<String, String> extractViolations(Set<ConstraintViolation<T>> violations) {
  Map<String, String> errors = new HashMap<>();
  for (ConstraintViolation<T> v: violations) {
    errors.put(v.getPropertyPath().toString(), "["+v.getPropertyPath().toString()+"] " + StringUtils.capitalize(v.getMessage()));
  }
  return errors;
  }
```

以下的`raiseFirstError`方法不是特定标准的，这是我们向客户端呈现服务器端错误的方式：

```java
  public static void raiseFirstError(BindingResult result) {
    if (result.hasErrors()) {
      throw new IllegalArgumentException(result.getAllErrors().get(0).getCode());
    }
else if (result.hasGlobalErrors()) {
throw new IllegalArgumentException(result.getGlobalError().getDefaultMessage());
       }
}
}
```

1.  根据第四章，*为无状态架构构建 REST API*，cloudstreetmarket-api 的`RestExceptionHandler`仍然配置为处理`IllegalArgumentExceptions`，并以`ErrorInfo`格式化的响应呈现它们：

```java
@ControllerAdvice
public class RestExceptionHandler extends ResponseEntityExceptionHandler {
  @Autowired
  private ResourceBundleService bundle;
   @Override
  protected ResponseEntity<Object> handleExceptionInternal(Exception ex, Object body,
    HttpHeaders headers, HttpStatus status, WebRequest request) {
    ErrorInfo errorInfo = null;
    if(body!=null && bundle.containsKey(body.toString())){
        String key = body.toString();
        String localizedMessage = bundle.get(key);
        errorInfo = new ErrorInfo(ex, localizedMessage, key, status);
    }
    else{
      errorInfo = new ErrorInfo(ex, (body!=null)? body.toString() : null, null, status);
    }
return new ResponseEntity<Object>(errorInfo, headers, status);
}
  @ExceptionHandler({ InvalidDataAccessApiUsageException.class, DataAccessException.class, IllegalArgumentException.class })
  protected ResponseEntity<Object> handleConflict(final RuntimeException ex, final WebRequest request) {
      return handleExceptionInternal(ex, I18N_API_GENERIC_REQUEST_PARAMS_NOT_VALID, new HttpHeaders(), BAD_REQUEST, request);
    }
}
```

1.  在 UI 改进中浏览，您会注意到一个用于更新用户**首选项**的新表单。通过**登录**菜单可以访问这个表单，如下面的截图所示：![如何做…](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00889.jpeg)![如何做…](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00890.jpeg)

1.  在这个用户**首选项**表单中，当前端验证被停用（前端验证将在本章的最后一个配方中开发），不填写电子邮件字段会导致以下（可定制的）`ErrorInfo`对象在 HTTP 响应中：

```java
{"error":"[email] Size must be between 4 and 30",
"message":"The request parameters were not valid!",
"i18nKey":"error.api.generic.provided.request.parameters.not.valid",
"status":400,
"date":"2016-01-05 05:59:26.584"}
```

1.  在前端，为了处理这个错误，`accountController`（在`account_management.js`中）实例化时依赖于一个自定义的`errorHandler`工厂。代码如下：

```java
cloudStreetMarketApp.controller('accountController', function ($scope, $translate, $location, errorHandler, accountManagementFactory, httpAuth, genericAPIFactory){
      $scope.form = {
      id: "",
    email: "",
    fullName: "",
    password: "",
    language: "EN",
    currency: "",
    profileImg: "img/anon.png"
      };
  ...
}
```

1.  `accountController`有一个`update`方法，调用`errorHandler.renderOnForm`方法：

```java
  $scope.update = function () {
    $scope.formSubmitted = true;

    if(!$scope.updateAccount.$valid) {
        return;
    }
      httpAuth.put('/api/users', JSON.stringify($scope.form)).success(
      function(data, status, headers, config) {
        httpAuth.setCredentials($scope.form.id, $scope.form.password);
      $scope.updateSuccess = true;
      }
    ).error(function(data, status, headers, config) {
        $scope.updateFail = true;
        $scope.updateSuccess = false;
        $scope.serverErrorMessage = errorHandler.renderOnForms(data);
      }
    );
  };
```

1.  `main_menu.js`中定义了`errorHandler`如下。它具有从`i18n`代码中提取翻译消息的能力：

```java
cloudStreetMarketApp.factory("errorHandler", ['$translate', function ($translate) {
    return {
        render: function (data) {
        if(data.message && data.message.length > 0){
          return data.message;
        }
        else if(!data.message && data.i18nKey && data.i18nKey.length > 0){
          return $translate(data.i18nKey);
          }
        return $translate("error.api.generic.internal");
        },
        renderOnForms: function (data) {
        if(data.error && data.error.length > 0){
          return data.error;
        }
        else if(data.message && data.message.length > 0){
          return data.message;
        }
        else if(!data.message && data.i18nKey && data.i18nKey.length > 0){
          return $translate(data.i18nKey);
        }
        return $translate("error.api.generic.internal");
        }
    }
}]);
```

**首选项**表单如下所示：

![如何做…](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00891.jpeg)

### 提示

正如我们所说，要模拟这个错误，前端验证需要被停用。这可以通过在`user-account.html`中的`<form name="updateAccount" … novalidate>`标记中添加一个`novalidate`属性来实现。

1.  在服务器端，我们还为财务交易实体创建了一个自定义验证器。这个验证器利用了 Spring 的`ValidationUtils`：

```java
@Component
public class TransactionValidator implements Validator {
  @Override
  public boolean supports(Class<?> clazz) {
    return Transaction.class.isAssignableFrom(clazz);
  }
  @Override
  public void validate(Object target, Errors errors) {
    ValidationUtils.rejectIfEmpty(errors, "quote", " transaction.quote.empty");
    ValidationUtils.rejectIfEmpty(errors, "user", " transaction.user.empty");
    ValidationUtils.rejectIfEmpty(errors, "type", " transaction.type.empty");
  }
}
```

## 工作原理...

### 使用 Spring 验证器

Spring 提供了一个`Validator`接口(`org.sfw.validation.Validator`)，用于创建要注入或实例化在我们想要的层中的组件。因此，Spring 验证组件可以在 Spring MVC 控制器中使用。`Validator`接口如下：

```java
public interface Validator {
  boolean supports(Class<?> clazz);
  void validate(Object target, Errors errors);
}
```

`supports(Class<?> clazz)`方法用于评估`Validator`实现的域，也用于限制其使用到特定类型或超类型。

`validate(Object target, Errors errors)`方法规定了其标准，使得验证器的验证逻辑存在于这个位置。传递的`target`对象被评估，验证的结果存储在`org.springframework.validation.Errors`接口的实例中。这里显示了`Errors`接口的部分预览：

```java
public interface Errors {
  ...
  void reject(String errorCode);
  void reject(String errorCode, String defaultMessage);
void reject(String errorCode, Object[] errorArgs, String defaultMessage);
void rejectValue(String field, String errorCode); void rejectValue(String field, String errorCode, String defaultMessage);
void rejectValue(String field, String errorCode, Object[] errorArgs, String defaultMessage);
  void addAllErrors(Errors errors);
  boolean hasErrors();
  int getErrorCount();
  List<ObjectError> getAllErrors();
  ...
}
```

使用 Spring MVC，我们有可能将`Validator`绑定和触发到特定的方法处理程序。框架会寻找绑定到传入请求的验证器实例。我们在*第四步*的配方中配置了这样的绑定：

```java
  @InitBinder
    protected void initBinder(WebDataBinder binder) {
        binder.setValidator(new UserValidator());
    }
```

### 提示

我们已经使用了 `@InitBinder` 注解将其他对象（格式化程序）附加到传入请求（参见第四章 *构建无状态架构的 REST API* 中的 *绑定请求，编组响应* 教程）。

`Binders` (`org.springframework.validation.DataBinder`) 允许将属性值设置到目标对象上。Binders 还提供了对验证和绑定结果分析的支持。

`DataBinder.validate()` 方法在每个绑定步骤之后被调用，这个方法调用了附加到 `DataBinder` 的主验证器的 `validate`。

绑定过程填充了一个结果对象，这是 `org.springframework.validation.BindingResult` 接口的一个实例。可以使用 `DataBinder.getBindingResult()` 方法检索此结果对象。

实际上，`BindingResult` 实现也是一个 `Errors` 实现（如此处所示）。我们之前介绍过 `Errors` 接口。查看以下代码：

```java
public interface BindingResult extends Errors {
  Object getTarget();
  Map<String, Object> getModel();
  Object getRawFieldValue(String field);
  PropertyEditor findEditor(String field, Class<?> valueType);
  PropertyEditorRegistry getPropertyEditorRegistry();
  void addError(ObjectError error);
  String[] resolveMessageCodes(String errorCode);
  String[] resolveMessageCodes(String errorCode, String field);
  void recordSuppressedField(String field);
  String[] getSuppressedFields();
}
```

整个设计可以总结如下：

我们创建了一个验证器实现。当特定控制器方法处理程序的传入请求到达时，请求有效负载将转换为由 `@RequestBody` 注解（在我们的案例中是一个 `Entity`）所针对的类的实例。我们的验证器实现的一个实例绑定到注入的 `@RequestBody` 对象上。如果注入的 `@RequestBody` 对象使用 `@Valid` 注解定义，框架会要求 `DataBinder` 在每个绑定步骤上验证对象，并将错误存储在 `DataBinder` 的 `BindingResultobject` 中。

最后，这个 `BindingResult` 对象被注入为方法处理程序的参数，因此我们可以决定如何处理它的错误（如果有的话）。在绑定过程中，缺少字段和属性访问异常被转换为 `FieldErrors`。这些 `FieldErrors` 也被存储到 `Errors` 实例中。以下错误代码用于 `FieldErrors`：

```java
Missing field error: "required"
Type mismatch error: "typeMismatch"
Method invocation error: "methodInvocation"
```

当需要为用户返回更好的错误消息时，`MessageSource` 帮助我们处理查找并从 `MessageSourceResolvable` 实现中检索正确的本地化消息，方法如下：

```java
MessageSource.getMessage(org.sfw.context.MessageSourceResolvable, java.util.Locale). 
```

### 提示

`FieldError` 扩展了 `ObjectError`，而 `ObjectError` 扩展了 `DefaultMessageSourceResolvable`，它是 `MessageSourceResolvable` 的实现。

#### ValidationUtils

`ValodationUtils` 实用程序类 (`org.sfw.validation.ValidationUtils`) 提供了一些方便的静态方法，用于调用验证器和拒绝空字段。这些实用方法允许一行断言，同时处理 `Errors` 对象的填充。在这个教程中，第 14 步详细介绍了我们的 `TransactionValidator` 如何使用 `ValidationUtils`。

#### I18n 验证错误

下一个教程将专注于错误和内容的国际化。然而，让我们看看我们如何从控制器捕获错误以及如何显示它们。`UserController` 的 `update` 方法在第一行有这个自定义方法调用：

```java

ValidatorUtil.raiseFirstError(result);
```

我们为我们的需求创建了 `ValidatorUtil` 支持类；想法是对我们的验证器可以检测到的任何类型的错误抛出 `IllegalArgumentException`。`ValidatorUtil.raiseFirstError(result)` 方法调用也可以在 `TransactionController.update(…)` 方法处理程序中找到。这个方法处理程序依赖于 *第 14 步* 中介绍的 `TransactionValidator`。

如果你还记得这个 `TransactionValidator`，当财务交易对象中不存在报价对象时，它会创建一个带有 `transaction.quote.empty` 消息代码的错误。然后会抛出一个带有 `transaction.quote.empty` 消息详细信息的 `IllegalArgumentException`。

在下一个教程中，我们将重新审视如何构建并从 `IllegalArgumentException` 发送适当的国际化 JSON 响应给客户端。

### 使用 JSR-303/JSR-349 Bean 验证

Spring Framework 4 及以上版本支持 bean 验证 1.0（JSR-303）和 bean 验证 1.1（JSR-349）。它还将此 bean 验证适配到`Validator`接口，并允许使用注解创建类级验证器。

JSR-303 和 JSR-349 这两个规范定义了一组适用于 bean 的约束，作为`javax.validation.constraints`包中的注解。

通常，使用规范中的代码而不是实现中的代码的一个很大的优势是我们不必知道使用的是哪个实现。此外，实现总是可以潜在地被另一个实现替换。

Bean 验证最初是为持久性 bean 设计的。即使规范与 JPA 的耦合度相对较低，参考实现仍然是 Hibernate 验证器。具有支持这些验证规范的持久性提供程序绝对是一个优势。现在有了 JPA2，持久性提供程序在持久化之前会自动调用 JSR-303 验证。确保来自两个不同层（控制器和模型）的这些验证会提高我们的信心水平。

#### 字段约束注解

我们在所呈现的`User`实体上定义了`@NotNull`和`@Size` JSR-303 注解。显然，在规范中可以找到的注解不止两个。

这里是 JEE7 中`javax.validation.constraints`注解包的摘要表：

| 注解类型 | 描述 |
| --- | --- |
| `AssertFalse` | 被注释的元素必须为 false。 |
| `AssertFalse.List` | 在同一个元素上定义了几个`AssertFalse`注解。 |
| `AssertTrue` | 被注释的元素必须为 true。 |
| `AssertTrue.List` | 在同一个元素上定义了几个`AssertTrue`注解。 |
| `DecimalMax` | 被注释的元素必须是一个数，其值必须低于或等于指定的最大值。 |
| `DecimalMax.List` | 在同一个元素上定义了几个`DecimalMax`注解。 |
| `DecimalMin` | 被注释的元素必须是一个数，其值必须高于或等于指定的最小值。 |
| `DecimalMin.List` | 在同一个元素上定义了几个`DecimalMin`注解。 |
| `Digits` | 被注释的元素必须是在接受范围内的数字。支持的类型有：`BigDecimal`、`BigInteger`、`CharSequence`、`byte`、`short`、`int`、`long`及其相应的包装类型。但是，`null`元素被视为有效。 |
| `Digits.List` | 在同一个元素上定义了几个`Digits`注解。 |
| `Future` | 被注释的元素必须是将来的日期。 |
| `Future.List` | 在同一个元素上定义了几个`Future`注解。 |
| `Max` | 被注释的元素必须是一个数，其值必须低于或等于指定的最大值。 |
| `Max.List` | 在同一个元素上定义了几个`Max`注解。 |
| `Min` | 被注释的元素必须是一个数，其值必须高于或等于指定的最小值。 |
| `Min.List` | 在同一个元素上定义了几个`Min`注解。 |
| `NotNull` | 被注释的元素不得为`null`。 |
| `NotNull.List` | 在同一个元素上定义了几个`NotNull`注解。 |
| `Past` | 被注释的元素必须是过去的日期。 |
| `Past.List` | 在同一个元素上定义了几个`Past`注解。 |
| `Pattern` | 被注释的`CharSequence`必须匹配指定的正则表达式。 |
| `Pattern.List` | 在同一个元素上定义了几个`Pattern`注解。 |
| `Size` | 被注释的元素大小必须在指定的边界之间（包括在内）。 |
| `Size.List` | 在同一个元素上定义了几个`Size`注解。 |

##### 特定于实现的约束

Bean 验证实现也可以超出规范，并提供它们自己的一组额外验证注释。Hibernate 验证器有一些有趣的注释，如`@NotBlank`，`@SafeHtml`，`@ScriptAssert`，`@CreditCardNumber`，`@Email`等。这些都列在 hibernate 文档中，可在以下 URL 访问

[`docs.jboss.org/hibernate/validator/4.3/reference/en-US/html_single/#table-custom-constraints`](http://docs.jboss.org/hibernate/validator/4.3/reference/en-US/html_single/#table-custom-constraints)

#### LocalValidator（可重用）

我们在 Spring 上下文中定义了以下验证器 bean：

```java
<bean id="validator" class="org.sfw.validation.beanvalidation.LocalValidatorFactoryBean"/>
```

此 bean 生成实现 JSR-303 和 JSR-349 的验证器实例。您可以在这里配置特定的提供程序类。默认情况下，Spring 在类路径中查找 Hibernate Validator JAR。一旦定义了这个 bean，它就可以被注入到需要的任何地方。

我们已经在我们的`UserValidator`中注入了这样的验证器实例，这使其符合 JSR-303 和 JSR-349。

对于国际化，验证器生成其一组默认消息代码。这些默认消息代码和值看起来像下面这样：

```java
javax.validation.constraints.Max.message=must be less than or equal to {value}
javax.validation.constraints.Min.message=must be greater than or equal to {value}
javax.validation.constraints.Pattern.message=must match "{regexp}"
javax.validation.constraints.Size.message=size must be between {min} and {max}
```

请随意在您自己的资源文件中覆盖它们！

## 还有更多…

在本节中，我们突出了一些我们没有解释的验证概念和组件。

### ValidationUtils

`ValidationUtils` Spring 实用程序类提供了方便的静态方法，用于调用`Validator`并拒绝填充错误对象的空字段，一行中的错误对象：

[`docs.spring.io/spring/docs/3.1.x/javadoc-api/org/springframework/validation/ValidationUtils.html`](http://docs.spring.io/spring/docs/3.1.x/javadoc-api/org/springframework/validation/ValidationUtils.html)

### 分组约束

我们可以将约束耦合到多个字段上，以定义一组更高级的约束：

[`beanvalidation.org/1.1/spec/#constraintdeclarationvalidationpr ocess-groupsequence`](http://beanvalidation.org/1.1/spec/#constraintdeclarationvalidationpr%20ocess-groupsequence)

[`docs.jboss.org/hibernate/stable/validator/reference/en-US/ html_single/#chapter-groups`](http://docs.jboss.org/hibernate/stable/validator/reference/en-US/%20html_single/#chapter-groups)

### 创建自定义验证器

有时创建一个具有自己注释的特定验证器可能很有用。检查链接，它应该带我们到：

[`howtodoinjava.com/2015/02/12/spring-mvc-custom-validator-example/`](http://howtodoinjava.com/2015/02/12/spring-mvc-custom-validator-example/)

### 关于验证的 Spring 参考

最好的信息来源仍然是 Spring 关于`Validation`的参考。检查链接，它应该带我们到：

[`docs.spring.io/spring/docs/current/spring-framework-reference/html/validation.html`](http://docs.spring.io/spring/docs/current/spring-framework-reference/html/validation.html)

## 另请参阅

+   整个 bean 验证规范（JSR-303 和 JSR-349）都有自己的网站：[`beanvalidation.org/1.1/spec`](http://beanvalidation.org/1.1/spec)。

# 为 REST 国际化消息和内容

在谈论国际化内容和消息之前，有必要谈论验证。对于全球和基于云的服务，仅支持一种语言的内容通常是不够的。

在这个示例中，我们提供了一个适合我们设计的实现，因此继续满足我们的可扩展性标准，不依赖于 HTTP 会话。

我们将看到如何定义`MessageSource` bean 来获取给定位置的最合适的消息。我们将看到如何序列化资源属性，使其可用于前端。我们将在前端使用 AngularJS 和 angular-translate 实现内容的动态翻译。

## 如何做…

在这个示例中，既有后端工作，也有前端工作。

### 后端

1.  以下 bean 已在核心上下文（`csm-core-config.xml`）中注册：

```java
<bean id="messageBundle" class="edu.zc.csm.core.i18n.SerializableResourceBundleMessageSource">
<property name="basenames" value="classpath:/META-INF/i18n/messages,classpath:/META-INF/i18n/errors"/>
  <property name="fileEncodings" value="UTF-8" />
  <property name="defaultEncoding" value="UTF-8" />
</bean>
```

1.  这个 bean 引用了一个创建的`SerializableResourceBundleMessageSource`，它收集资源文件并提取属性：

```java
/**
 * @author rvillars
 * {@link https://github.com/rvillars/bookapp-rest} 
 */
public class SerializableResourceBundleMessageSource extends ReloadableResourceBundleMessageSource {
   public Properties getAllProperties(Locale locale) {
      clearCacheIncludingAncestors();
      PropertiesHolder propertiesHolder = getMergedProperties(locale);
      Properties properties = propertiesHolder.getProperties();
    return properties;
  }
}
```

1.  这个 bean 包从两个地方访问：

新创建的`PropertiesController`公开（序列化）特定位置（这里只是语言）的所有消息和错误：

```java
@RestController
@ExposesResourceFor(Transaction.class)
@RequestMapping(value="/properties")
public class PropertiesController{
  @Autowired
  protected SerializableResourceBundleMessageSource messageBundle;
  @RequestMapping(method = RequestMethod.GET, produces={"application/json; charset=UTF-8"})
  @ResponseBody
  public Properties list(@RequestParam String lang) {
    return messageBundle.getAllProperties(new Locale(lang));
  }
}
```

已构建了一个特定的服务层，用于轻松地在控制器和服务之间提供消息和错误：

```java
@Service
@Transactional(readOnly = true)
public class ResourceBundleServiceImpl implements ResourceBundleService {
  @Autowired
protected SerializableResourceBundleMessageSource messageBundle;
  private static final Map<Locale, Properties> localizedMap = new HashMap<>();
  @Override
  public Properties getAll() {
    return getBundleForUser();
  }
  @Override
  public String get(String key) {
    return getBundleForUser().getProperty(key);
  }
  @Override
  public String getFormatted(String key, String... arguments) {
    return MessageFormat.format( getBundleForUser().getProperty(key), arguments
    );
  }
  @Override
  public boolean containsKey(String key) {
    return getAll().containsKey(key);
  }
  private Properties getBundleForUser(){
    Locale locale = AuthenticationUtil.getUserPrincipal().getLocale();
    if(!localizedMap.containsKey(locale)){
      localizedMap.put(locale, messageBundle.getAllProperties(locale));
    }
    return localizedMap.get(locale);
}
}
```

### 注意

`ResourceBundleServiceImpl`目前使用相同的`SerializableResourceBundleMessageSource`。它还从已登录用户（Spring Security）中提取区域设置，如果失败则回退到英语。

1.  这个`ResourceBundleServiceImpl`服务被注入到我们的`WebContentInterceptor` `CloudstreetApiWCI:`中

```java
  @Autowired
  protected ResourceBundleService bundle;
```

1.  例如，在`TransactionController`中，bundle 被定位以提取错误消息：

```java
if(!transaction.getUser().getUsername()
    .equals(getPrincipal().getUsername())){
  throw new AccessDeniedException( bundle.get(I18nKeys.I18N_TRANSACTIONS_USER_FORBIDDEN)
);
}
```

1.  `I18nKeys`只是一个承载资源键的常量的类：

```java
public class I18nKeys {
  //Messages
public static final String I18N_ACTION_REGISTERS = "webapp.action.feeds.action.registers";
public static final String I18N_ACTION_BUYS = "webapp.action.feeds.action.buys";
public static final String I18N_ACTION_SELLS = "webapp.action.feeds.action.sells";
 ...
}
```

1.  资源文件位于核心模块中：![后端](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00892.jpeg)

### 前端

1.  在`index.jsp`中添加了两个 angular-translate 的依赖项：

```java
<script src="img/angular-translate.min.js"></script>
<script src="img/angular-translate-loader-url.min.js"></script>
```

1.  在`index.jsp`中配置翻译模块如下：

```java
cloudStreetMarketApp.config(function ($translateProvider) {
   	$translateProvider.useUrlLoader('/api/properties.json');
  $translateProvider.useStorage('UrlLanguageStorage');
  $translateProvider.preferredLanguage('en');
  $translateProvider.fallbackLanguage('en');
});
```

### 注意

您可以看到它定位到我们的 API 端点，只提供消息和错误。

1.  用户语言是从主菜单(`main_menu.js`)中设置的。用户被加载，并且语言从用户对象中提取（默认为 EN）：

```java
cloudStreetMarketApp.controller('menuController',  function ($scope, $translate, $location, modalService, httpAuth, genericAPIFactory) {
    $scope.init = function () {
    ...
  genericAPIFactory.get("/api/users/"+httpAuth.getLoggedInUser()+".json")
  .success(function(data, status, headers, config) {
      $translate.use(data.language);
      $location.search('lang', data.language);
  });
  }
  ...
  }
```

1.  在 DOM 中，i18n 内容直接引用通过翻译指令进行翻译。例如，在`stock-detail.html`文件中查看：

```java
<span translate="screen.stock.detail.will.remain">Will remain</span>
```

`index-detail.html`文件中的另一个例子如下：

```java
<td translate>screen.index.detail.table.prev.close</td>
```

在`home.html`中，您可以找到其值如下翻译的作用域变量：

```java
{{value.userAction.presentTense | translate}}
```

1.  在应用程序中，更新您的个人偏好设置，并将您的语言设置为**法语**。例如，尝试访问可以从**stock-search**结果到达的**stock-detail**页面：![前端](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00893.jpeg)

1.  从**stock-detail**页面，您可以处理一个交易（用法语！）：![前端](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00894.jpeg)

## 它是如何工作的...

让我们来看看后端的变化。您首先需要了解的是自动装配的`SerializableResourceBundleMessageSource` bean，从中使用消息键提取国际化消息。

这个 bean 扩展了特定的`MessageSource`实现。存在几种类型的`MessageSource`，重要的是要理解它们之间的区别。我们将重新访问从用户那里提取`Locale`的方式，并看看如何使用`LocaleResolver`根据不同的可读性路径（会话、Cookie、接受标头等）来读取或猜测用户语言。

### MessageSource beans

首先，`MessageSource`是一个 Spring 接口（`org.sfw.context.MessageSource`）。`MessageSource`对象负责从不同的参数解析消息。

最有趣的参数是我们想要的消息的键和`Locale`（语言/国家组合），它将驱动正确的语言选择。如果没有提供`Locale`，或者`MessageSource`无法解析匹配的语言/国家文件或消息条目，它将退回到更通用的文件，并再次尝试，直到达到成功的解析。

如图所示，`MessageSource`实现仅公开`getMessage(…)`方法：

```java
public interface MessageSource {
  String getMessage(String code, Object[] args, String defaultMessage, Locale locale);
  String getMessage(String code, Object[] args, Locale locale) throws NoSuchMessageException;
  String getMessage(MessageSourceResolvable resolvable, Locale locale) throws NoSuchMessageException;
}
```

这个轻量级接口由 Spring 中的几个对象实现（特别是在上下文组件中）。但是，我们特别寻找`MessageSource`实现，Spring 4+中有三个特别值得一提。

#### ResourceBundleMessageSource

这个`MessageSource`实现使用指定的基本名称访问资源包。它依赖于底层 JDK 的`ResourceBundle`实现，结合 JDK 的标准消息解析提供的`MessageFormat`(`java.text.MessageFormat`)。

对于每条消息，访问的`ResourceBundle`实例和生成的`MessageFormat`都被缓存。`ResourceBundleMessageSource`提供的缓存比`java.util.ResourceBundle`类的内置缓存要快得多。

使用`java.util.ResourceBundle`时，当 JVM 正在运行时无法重新加载 bundle。因为`ResourceBundleMessageSource`依赖于`ResourceBundle`，它面临着相同的限制。

#### ReloadableResourceBundleMessageSource

与`ResourceBundleMessageSource`相比，这个类使用`Properties`实例作为消息的自定义数据结构。它通过使用 Spring Resource 对象的`PropertiesPersister`策略加载它们。

这种策略不仅能够根据时间戳更改重新加载文件，还能以特定字符编码加载属性文件。

`ReloadableResourceBundleMessageSource`支持使用`cacheSeconds`设置重新加载属性文件，并支持以编程方式清除属性缓存。

用于识别资源文件的基本名称是使用`basenames`属性（在 ReloadableResourceBundleMessageSource 配置中）定义的。定义的基本名称遵循基本的`ResourceBundle`约定，不指定文件扩展名或语言代码。我们可以引用任何 Spring 资源位置。使用`classpath`前缀，资源仍然可以从类路径加载，但在这种情况下，除了`-1`（永久缓存）之外的`cacheSeconds`值将不起作用。

#### StaticMessageSource

`StaticMessageSource`是一个简单的实现，允许以编程方式注册消息。它适用于测试而不是在生产中使用。

### 我们的 MessageSource bean 定义

我们实现了一个特定的控制器，用于序列化和公开我们资源包属性文件（错误和消息）的整个聚合，传递给作为查询参数的特定语言。

为了实现这一点，我们创建了一个自定义的`SerializableResourceBundleMessageSource`对象，借鉴了 Roger Villars 的*bookapp-rest*应用程序（[`github.com/rvillars/bookapp-rest`](https://github.com/rvillars/bookapp-rest)）。

这个自定义的`MessageSource`对象扩展了`ReloadableResourceBundleMessageSource`。我们已经用以下定义将其作为 Spring bean：

```java
<bean id="messageBundle" class="edu.zc.csm.core.i18n.SerializableResourceBundleMessageSource">
<property name="basenames" value="classpath:/META-INF/i18n/messages,classpath:/META-INF/i18n/errors"/>
  <property name="fileEncodings" value="UTF-8" />
  <property name="defaultEncoding" value="UTF-8" />
</bean>
```

我们已经在类路径中具体指定了资源文件的路径。这可以通过上下文中的全局资源 bean 来避免：

```java
<resources location="/, classpath:/META-INF/i18n" mapping="/resources/**"/>
```

请注意，Spring MVC 默认情况下期望 i18n 资源文件位于`/WEB-INF/i18n`文件夹中。

### 使用 LocaleResolver

在我们的应用程序中，为了将`Locale`切换到另一种语言/国家，我们通过用户偏好屏幕。这意味着我们以某种方式将这些信息持久化到数据库中。这使得`LocaleResolution`变得容易，实际上是在客户端上操作，读取用户数据并异步调用语言偏好的国际化消息。

然而，一些其他应用程序可能希望在服务器端操作`LocaleResolution`。为此，必须注册一个`LocaleResolver` bean。

`LocaleResolver`是一个 Spring 接口（`org.springframework.web.servlet.LocaleResolver`）：

```java
public interface LocaleResolver {
  Locale resolveLocale(HttpServletRequest request);
  void setLocale(HttpServletRequest request, HttpServletResponse response, Locale locale);
}
```

在 Spring MVC（版本四及以上）中有四种具体的实现：

#### AcceptHeaderLocaleResolver

AcceptHeaderLocaleResolver 利用 HTTP 请求的`Accept-Language`头。它提取值中包含的第一个 Locale。这个值通常由客户端的 Web 浏览器设置，从操作系统配置中读取。

#### FixedLocaleResolver

这个解析器总是返回一个固定的默认 Locale，可选地带有一个时区。默认的 Locale 是当前 JVM 的默认 Locale。

#### SessionLocaleResolver

当应用程序实际上使用用户会话时，这个解析器是最合适的。它读取并设置一个会话属性，其名称仅用于内部使用：

```java
public static final String LOCALE_SESSION_ATTRIBUTE_NAME = SessionLocaleResolver.class.getName() + ".LOCALE";
```

默认情况下，它从默认的`Locale`或`Accept-Language`头部设置值。会话还可以可选地包含一个关联的时区属性。或者，我们可以指定一个默认时区。

在这些情况下的最佳实践是创建一个额外的特定的 Web 过滤器。

#### CookieLocaleResolver

`CookieLocaleResolver`是一个适用于像我们这样的无状态应用程序的解析器。可以使用`cookieName`属性自定义 cookie 名称。如果在内部定义的请求参数中找不到`Locale`，它会尝试读取 cookie 值，并回退到`Accept-Language`头部。

cookie 还可以可选地包含一个关联的时区值。我们也可以指定一个默认时区。

## 还有更多...

### 使用 angular-translate.js 在客户端进行翻译

我们使用`angular-translate.js`来处理翻译，并从客户端端切换用户区域设置。`angular-translate.js`库非常完整并且有很好的文档。作为一个依赖项，它非常有用。

这个产品的主要点是提供：

+   组件（过滤器/指令）来翻译内容

+   异步加载 i18n 数据

+   使用`MessageFormat.js`支持复数形式

+   通过易于使用的接口进行扩展

这个图中显示了**angular-translate**的简要概述：

![使用 angular-translate.js 在客户端进行翻译](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00895.jpeg)

国际资源可以从 API 端点动态拉取（就像我们所做的那样），也可以从发布在 Web 应用程序路径上的静态资源文件中拉取。这些特定区域设置的资源存储在客户端上，可以使用`LocalStorage`或`cookies`。

存储的数据对应于一个变量（在我们的情况下是`UrlLanguageStorage`），该变量可以在任何可能需要翻译功能的模块中访问和注入。

如下例所示，`translate`指令可用于实际呈现翻译的消息：

```java
  <span translate>i18n.key.message</span> or  
  <span translate=" i18n.key.message" >fallBack translation in English (better for Google indexes) </span>
```

或者，我们可以使用预定义的翻译过滤器来在 DOM 中翻译我们的翻译键，而不让任何控制器或服务知道它们：

```java
{{data.type.type == 'BUY' ? 'screen.stock.detail.transaction.bought' : 'screen.stock.detail.transaction.sold' | translate}}
```

您可以在他们非常完善的文档中了解更多关于 angular-translate 的信息：

[`angular-translate.github.io`](https://angular-translate.github.io)

# 使用 HTML5 AngularJS 验证客户端表单

验证提交的数据在前端和后端都是一个很好的实践。谈到验证，区分用户体验和数据完整性保护也是很好的。这两者是两个不同的责任，可能由不同的团队负责。

我们相信*前端*验证已经取代了以前由*后端*管理的表单验证。在一个 API 与 Web 内容解耦的可扩展环境中，验证体验现在是客户端界面的责任，可以是多个（甚至由第三方实现）如网站、移动网站、移动应用等。

在这个示例中，我们将专注于表单验证，更具体地说是 AngularJS 表单验证。

## 如何做...

1.  让我们再次考虑**用户首选项**表单。这是 HTML 定义（`user-account.html`）：

```java
<form name="updateAccount" action="#" ng-class="formSubmitted ? 'submitted':''">
  <fieldset>
    <div class="clearfix span">
      <label for="id" translate> screen.preference.field.username</label>
        <div class="input">
<input type="text" name="id" placeholder="Username" ng-model="form.id" ng-minlength="4" ng-maxlength="15" readonly required/>
<span class="text-error" ng-show="formSubmitted && updateAccount.id.$error.required" translate>   error.webapp.user.account.username.required</span>
        </div>
<label for="email" translate> screen.preference.field.email</label>
      <div class="input">
<input type="email" name="email" placeholder="Email" ng-model="form.email"/>
<span class="text-error" ng-show="formSubmitted && 
  updateAccount.email.$error" translate>error.webapp.user.account.email</span>
      </div>
<label for="password" translate> screen.preference.field.password</label>
      <div class="input">
<input type="password" name="password" ng-minlength="5" placeholder="Please type again" ng-model="form.password" required/>
<span class="text-error" ng-show="formSubmitted && updateAccount.password.$error.required" translate>   error.webapp.user.account.password.type.again</span>
<span class="text-error" ng-show="formSubmitted && updateAccount.password.$error.minlength" translate>   error.webapp.user.account.password.too.short</span>
</div>   
<label for="fullname" translate>   screen.preference.field.full.name</label>
        <div class="input" >
<input type="text" name="fullname" placeholder="Full name" ng-model="form.fullname"/>
        </div>
<label for="currencySelector" translate>   screen.preference.field.preferred.currency</label>
        <div class="input">
<select class="input-small"  id="currencySelector" ng-model="form.currency" ng-init="form.currency='USD'" ng-selected="USD" ng-change="updateCredit()">
        <option>USD</option><option>GBP</option>
        <option>EUR</option><option>INR</option>
        <option>SGD</option><option>CNY</option>
        </select>
        </div>
<label for="currencySelector" translate>   screen.preference.field.preferred.language</label>
        <div class="input">
      <div class="btn-group">
<button onclick="return false;" class="btn" tabindex="-1"><span class="lang-sm lang-lbl" lang="{{form.language | lowercase}}"></button>
<button class="btn dropdown-toggle" data-toggle="dropdown" tabindex="-1">
        <span class="caret"></span>
        </button>
       <ul class="dropdown-menu">
<li><a href="#" ng-click="setLanguage('EN')"><span class="lang-sm lang-lbl-full" lang="en"></span></a></li>
<li><a href="#" ng-click="setLanguage('FR')">  <span class="lang-sm lang-lbl-full" lang="fr"></span></a></li>
        </ul>
        </div>
        </div>
     </div>
  </fieldset>
</form>
```

1.  `account_management.js`控制器中的 JavaScript 部分包括两个引用函数和四个变量，用于控制表单验证及其样式：

```java
  $scope.update = function () {
      	$scope.formSubmitted = true;
      if(!$scope.updateAccount.$valid) {
       return;
  }
httpAuth.put('/api/users', JSON.stringify($scope.form)).success(
    function(data, status, headers, config) {
      httpAuth.setCredentials(
        $scope.form.id, $scope.form.password);
        $scope.updateSuccess = true;
        }).error(function(data,status,headers,config) {
          $scope.updateFail = true;
          $scope.updateSuccess = false;
$scope.serverErrorMessage = errorHandler.renderOnForms(data);
    });
 };
    $scope.setLanguage = function(language) {
    $translate.use(language);
    $scope.form.language = language;
   }

   //Variables initialization
   $scope.formSubmitted = false;
   $scope.serverErrorMessage ="";
   $scope.updateSuccess = false;
   $scope.updateFail = false;
```

已创建两个 CSS 类以正确呈现字段上的错误：

```java
.submitted  input.ng-invalid{
  border: 2px solid #b94a48;
  background-color: #EBD3D5;!important;
} 
.submitted .input .text-error {
  font-weight:bold;
  padding-left:10px;
}
```

1.  如果您尝试输入错误的电子邮件或者尝试在不输入密码的情况下提交表单，您应该观察到以下验证控件：![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00896.jpeg)

## 它是如何工作的...

AngularJS 提供了设置客户端表单验证的工具。与 AngularJS 一样，这些工具与现代 HTML5 技术和标准很好地集成在一起。

HTML5 表单提供了本地验证，可以使用标签和属性在不同的表单元素（输入、选择...）上定义基本字段验证（最大长度、必填...）

AngularJS 从一开始就完善和扩展了这些标准定义，使它们具有交互性和响应性，而且没有额外开销。

### 验证约束

让我们更仔细地看一下可以放置在表单控件上的可用验证选项。

#### 必填

`input`字段可以被标记为`required`（HTML5 标签）：

```java
<input type="text" required /> 
```

#### 最小/最大长度

`ng-minlength`指令可用于断言输入字符的数量是否达到给定的阈值：

```java
<input type="text" ng-minlength="3" /> 
```

同样，`ng-maxlength`可以大大限制输入字符的数量到最大值：

```java
<input type="text" ng-maxlength="15" /> 
```

#### 正则表达式模式

`ng-pattern`指令通常用于确保输入的数据与预定义的形状匹配：

```java
<input type="text" ng-pattern="[a-zA-Z]" />
```

#### 数字/电子邮件/URL

这些 HTML5 输入类型由 AngularJS 处理，以便限制在它们所代表的格式内：

```java
<input type="number" name="quantity" ng-model="form.quantity" />
<input type="email" name="email" ng-model=" form.email" />
<input type="url" name="destination" ng-model=" form.url" />
```

### 表单中的控制变量

AngularJS 在包含的`$scope`上发布属性，以匹配 DOM 中的表单状态。这使得 JavaScript 表单验证非常容易控制错误并呈现状态。

这些属性可以从以下结构中访问：

```java
  formName.inputFieldName.property
```

#### 修改/未修改状态

可以使用以下属性来评估这种状态：

```java
formName.inputFieldName.$pristine;
formName.inputFieldName.$dirty;
```

#### 有效/无效状态

可以根据字段或全局定义的验证来评估表单的有效状态：

```java
formName.inputFieldName.$valid;
formName.inputFieldName.$invalid;
formName.$valid;
formName.$invalid;
```

#### 错误

在我们之前定义的有效性评估之后，可以从`$error`属性中提取有关出现了什么问题的更多信息：

```java
myForm.username.$error.pattern
myForm.username.$error.required
myForm.username.$error.minlength
```

`$error`对象包含特定表单的所有验证信息，并反映这些验证是否令人满意。

### 表单状态转置和样式

与 AngularJS 一样，转置是为了将 DOM 状态与作用域绑定。因此，表单状态和控件状态会实时反映在 CSS 类中。这些 CSS 类可以被定义/覆盖，以便定义全局验证样式：

```java
input.ng-invalid {
  border: 1px solid red;
}
input.ng-valid {
  border: 1px solid green;
}
```

## 参见

+   **AngularJS 表单文档**：了解有关 AngularJS 表单验证功能的更多信息（我们只是在这里介绍了它们）：[`docs.angularjs.org/guide/forms`](https://docs.angularjs.org/guide/forms)

