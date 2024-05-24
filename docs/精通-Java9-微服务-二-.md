# 精通 Java9 微服务（二）

> 原文：[`zh.annas-archive.org/md5/EB1A7415EF02ADBBA3AE87C35F6AF10F`](https://zh.annas-archive.org/md5/EB1A7415EF02ADBBA3AE87C35F6AF10F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：实现微服务

本章将带你从设计阶段到我们示例项目的实现——一个**在线预订餐桌系统**（**OTRS**）。在这里，你将使用上一章中解释的相同设计并将其扩展以构建微服务。在本章结束时，你不仅学会了如何实现设计，还学会了微服务的不同方面——构建、测试和打包。虽然重点是构建和实现 Restaurant 微服务，但你也可以用相同的方法来构建和实现 OTRS 中使用的其他微服务。

在本章中，我们将介绍以下主题：

+   OTRS 概览

+   开发和实现微服务

+   测试

我们将使用上一章中展示的领域驱动设计的关键概念。在上一章中，你看到了如何使用核心 Java 开发领域模型。现在，我们将从示例领域实现转向 Spring Framework 驱动的实现。你将利用 Spring Boot 来实现领域驱动设计概念，并将它们从核心 Java 转换为基于 Spring Framework 的模型。

此外，我们还将使用 Spring Cloud，它提供了一个通过 Spring Boot 可用的云就绪解决方案。Spring Boot 将允许你使用依赖于 Tomcat 或 Jetty 的内嵌应用程序容器，你的服务被包装为 JAR 或 WAR。这个 JAR 作为一个独立的进程执行，一个微服务，将服务于提供对所有请求的响应，并指向服务中定义的端点。

Spring Cloud 也可以轻松集成 Netflix Eureka，一个服务注册和发现组件。OTRS 将使用它进行注册和微服务的发现。

# OTRS 概览

基于微服务原则，我们需要为每个功能分别拥有独立的微服务。在查看 OTRS 之后，我们可以很容易地将其划分为三个主要微服务——Restaurant 服务、预订服务和用户服务。在 OTRS 中还可以定义其他微服务。我们的重点是这三个微服务。想法是使它们独立，包括拥有自己的独立数据库。

我们可以如下总结这些服务的功能：

+   **餐厅服务**：这个服务提供了对餐厅资源的功能——**创建**、**读取**、**更新**、**删除**（**CRUD**）操作和基于标准的选择。它提供了餐厅和餐桌之间的关联。餐厅也会提供对`Table`实体的访问。

+   **用户服务**：这个服务，如名字所示，允许终端用户对用户实体执行 CRUD 操作。

+   **预订服务**：该服务利用餐厅服务和用户服务执行预订的 CRUD 操作。它将基于指定时间段的餐桌可用性进行餐厅搜索及其相关表格的查找和分配。它创建了餐厅/餐桌与用户之间的关系：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/7477a84d-be2b-4e19-88ec-d74b29e6b4c3.jpg)

微服务的注册和发现

前述图表展示了每个微服务如何独立工作。这就是微服务可以独立开发、改进和维护的原因，而不会影响其他服务。这些服务可以具有自己的分层架构和数据库。没有限制要求使用相同的技术、框架和语言来开发这些服务。在任何给定的时间点，您还可以引入新的微服务。例如，出于会计目的，我们可以引入一个会计服务，可以向餐厅提供簿记服务。同样，分析报告也是其他可以集成和暴露的服务。

出于演示目的，我们将只实现前述图表中显示的三个服务。

# 开发和实现微服务

我们将使用前章描述的领域驱动实现和方法来使用 Spring Cloud 实现微服务。让我们回顾一下关键工件：

+   **实体**：这些是可识别且在产品/服务状态中保持不变的对象类别。这些对象*不是*由它们的属性定义，而是由它们的标识和连续性线定义。实体具有诸如标识、连续性线和不会定义它们身份的属性等特征。

+   **值对象**（**VOs**）仅包含属性，没有概念上的身份。最佳实践是保持 VOs 作为不可变对象。在 Spring 框架中，实体是纯粹的 POJOs；因此，我们也将使用它们作为 VOs。

+   **服务对象**：这些在技术框架中很常见。在领域驱动设计中，这些也用于领域层。服务对象没有内部状态；它的唯一目的是向领域提供行为。服务对象提供不能与特定实体或 VOs 相关联的行为。服务对象可能向一个或多个实体或 VOs 提供一个或多个相关行为。在领域模型中明确定义服务是最佳实践。

+   **仓库对象**：仓库对象是领域模型的一部分，它与存储（如数据库、外部源等）交互，以检索持久化的对象。当接收到仓库中对象的引用请求时，它返回现有的对象引用。如果请求的对象在仓库中不存在，那么它从存储中检索该对象。

下载示例代码：详细的步骤说明在本书的前言中提到。请查看。本书的代码包也托管在 GitHub 上，地址为：[`github.com/PacktPublishing/Mastering-Microservices-with-Java`](https://github.com/PacktPublishing/Mastering-Microservices-with-Java-9-Second-Edition)。我们还有其他来自我们丰富的书籍和视频目录的代码包，地址为：[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)。查看它们！

每个 OTRS 微服务 API 代表一个 RESTful web 服务。OTRS API 使用 HTTP 动词（如`GET`、`POST`等），以及 RESTful 端点结构。请求和响应负载格式化为 JSON。如果需要，也可以使用 XML。

# 餐厅微服务

餐厅微服务将通过 REST 端点暴露给外部世界进行消费。在餐厅微服务示例中，我们会找到以下端点。根据需求可以添加尽可能多的端点：

1.  获取餐厅 ID 的端点：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/6dd6acef-2a4c-420e-b962-a11cbb7261f0.png)

1.  获取匹配查询参数`Name`的所有餐厅的端点：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/4967fca0-9a41-47dc-ba3f-14de1854d494.png)

1.  创建新餐厅的端点：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/c3956c15-b2bc-460b-b4a9-0904194f97c6.png)

同样，我们可以添加各种端点及其实现。为了演示目的，我们将使用 Spring Cloud 实现上述端点。

# OTRS 实现

我们将创建一个多模块的 Maven 项目来实现 OTRS。以下堆栈将用于开发 OTRS 应用程序。请注意，在撰写本书时，只有 Spring Boot 和 Cloud 的快照构建可用。因此，在最终发布中，可能会有一个或两个变化：

+   Java 版本 1.9

+   Spring Boot 2.0.0.M1

+   Spring Cloud Finchley.M2

+   Maven Compiler Plugin 3.6.1（用于 Java 1.9）

上述所有点都在根`pom.xml`中提到，还包括以下 OTRS 模块：

+   `eureka-service`

+   `restaurant-service`

+   `user-service`

+   `booking-service`

根`pom.xml`文件将如下所示：

```java
<?xml version="1.0" encoding="UTF-8"?> 
<project   xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd"> 
    <modelVersion>4.0.0</modelVersion> 

    <groupId>com.packtpub.mmj</groupId> 
    <artifactId>6392_chapter4</artifactId> 
    <version>PACKT-SNAPSHOT</version> 
    <name>6392_chapter4</name> 
    <description>Master Microservices with Java Ed 2, Chapter 4 - Implementing Microservices</description> 

    <packaging>pom</packaging> 
    <properties> 
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding> 
        <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding> 
        <java.version>1.9</java.version> 
        <maven.compiler.source>1.9</maven.compiler.source> 
        <maven.compiler.target>1.9</maven.compiler.target> 
    </properties> 

    <parent> 
        <groupId>org.springframework.boot</groupId> 
        <artifactId>spring-boot-starter-parent</artifactId> 
        <version>2.0.0.M1</version> 
    </parent> 
    <dependencyManagement> 
        <dependencies> 
            <dependency> 
                <groupId>org.springframework.cloud</groupId> 
                <artifactId>spring-cloud-dependencies</artifactId> 
                <version>Finchley.M2</version> 
                <type>pom</type> 
                <scope>import</scope> 
            </dependency> 
        </dependencies> 
    </dependencyManagement> 

    <modules> 
        <module>eureka-service</module> 
        <module>restaurant-service</module> 
        <module>booking-service</module> 
        <module>user-service</module> 
    </modules> 

    <!-- Build step is required to include the spring boot artifacts in generated jars --> 
    <build> 
        <finalName>${project.artifactId}</finalName> 
        <plugins> 
            <plugin> 
                <groupId>org.springframework.boot</groupId> 
                <artifactId>spring-boot-maven-plugin</artifactId> 
            </plugin> 
            <plugin> 
                <groupId>org.apache.maven.plugins</groupId> 
                <artifactId>maven-compiler-plugin</artifactId> 
                <version>3.6.1</version> 
                <configuration> 
                    <source>1.9</source> 
                    <target>1.9</target> 
                    <showDeprecation>true</showDeprecation> 
                    <showWarnings>true</showWarnings> 
                </configuration> 
            </plugin> 
        </plugins> 
    </build> 

    <!-- Added repository additionally as Finchley.M2 was not available in central repository --> 
    <repositories> 
        <repository> 
            <id>Spring Milestones</id> 
            <url>https://repo.spring.io/libs-milestone</url> 
            <snapshots> 
                <enabled>false</enabled> 
            </snapshots> 
        </repository> 
    </repositories> 

    <pluginRepositories> 
        <pluginRepository> 
            <id>Spring Milestones</id> 
            <url>https://repo.spring.io/libs-milestone</url> 
            <snapshots> 
                <enabled>false</enabled> 
            </snapshots> 
        </pluginRepository> 
    </pluginRepositories> 
</project> 
```

我们正在开发基于 REST 的微服务。我们将实现`restaurant`模块。`booking`和`user`模块是在类似的基础上开发的。

# 控制器类

`RestaurantController`类使用`@RestController`注解构建餐厅服务端点。我们在第二章中已经详细介绍了`@RestController`，*设置开发环境*。以下是

`@RestController`是一个类级注解，用于资源类。它是

`@Controller`和`@ResponseBody`注解的组合。它返回领域对象。

# API 版本控制

随着我们前进，我想与大家分享的是，我们在 REST 端点上使用了`v1`前缀。这代表了 API 的版本。我还想简要介绍一下 API 版本化的重要性。版本化 API 很重要，因为 API 会随着时间的推移而改变。您的知识和经验会随着时间而提高，这导致了 API 的变化。API 的变化可能会破坏现有的客户端集成。

因此，管理 API 版本有多种方法。其中一种是在路径中使用版本，或者有些人使用 HTTP 头。HTTP 头可以是一个自定义请求头或接受头，以表示调用 API 的版本。请参考 Bhakti Mehta 所著的《RESTful Java Patterns and Best Practices》，Packt Publishing 出版，[`www.packtpub.com/application-development/restful-java-patterns-and-best-practices`](https://www.packtpub.com/application-development/restful-java-patterns-and-best-practices)，以获取更多信息：

```java
@RestController 
@RequestMapping("/v1/restaurants") 
public class RestaurantController { 

    protected Logger logger = Logger.getLogger(RestaurantController.class.getName()); 

    protected RestaurantService restaurantService; 

    @Autowired 
    public RestaurantController(RestaurantService restaurantService) { 
        this.restaurantService = restaurantService; 
    } 

    /** 
     * Fetch restaurants with the specified name. A partial case-insensitive 
     * match is supported. So <code>http://.../restaurants/rest</code> will find 
     * any restaurants with upper or lower case 'rest' in their name. 
     * 
     * @param name 
     * @return A non-null, non-empty collection of restaurants. 
     */ 
    @RequestMapping(method = RequestMethod.GET) 
    public ResponseEntity<Collection<Restaurant>> findByName(@RequestParam("name") String name) { 

logger.info(String.format("restaurant-service findByName() invoked:{} for {} ", restaurantService.getClass().getName(), name)); 
        name = name.trim().toLowerCase(); 
        Collection<Restaurant> restaurants; 
        try { 
            restaurants = restaurantService.findByName(name); 
        } catch (Exception ex) { 
            logger.log(Level.WARNING, "Exception raised findByName REST Call", ex); 
            return new ResponseEntity< Collection< Restaurant>>(HttpStatus.INTERNAL_SERVER_ERROR); 
        } 
        return restaurants.size() > 0 ? new ResponseEntity< Collection< Restaurant>>(restaurants, HttpStatus.OK) 
                : new ResponseEntity< Collection< Restaurant>>(HttpStatus.NO_CONTENT); 
    } 

    /** 
     * Fetch restaurants with the given id. 
     * <code>http://.../v1/restaurants/{restaurant_id}</code> will return 
     * restaurant with given id. 
     * 
     * @param retaurant_id 
     * @return A non-null, non-empty collection of restaurants. 
     */ 
    @RequestMapping(value = "/{restaurant_id}", method = RequestMethod.GET) 
    public ResponseEntity<Entity> findById(@PathVariable("restaurant_id") String id) { 

       logger.info(String.format("restaurant-service findById() invoked:{} for {} ", restaurantService.getClass().getName(), id)); 
        id = id.trim(); 
        Entity restaurant; 
        try { 
            restaurant = restaurantService.findById(id); 
        } catch (Exception ex) { 
            logger.log(Level.SEVERE, "Exception raised findById REST Call", ex); 
            return new ResponseEntity<Entity>(HttpStatus.INTERNAL_SERVER_ERROR); 
        } 
        return restaurant != null ? new ResponseEntity<Entity>(restaurant, HttpStatus.OK) 
                : new ResponseEntity<Entity>(HttpStatus.NO_CONTENT); 
    } 

    /** 
     * Add restaurant with the specified information. 
     * 
     * @param Restaurant 
     * @return A non-null restaurant. 
     * @throws RestaurantNotFoundException If there are no matches at all. 
     */ 
    @RequestMapping(method = RequestMethod.POST) 
    public ResponseEntity<Restaurant> add(@RequestBody RestaurantVO restaurantVO) { 

        logger.info(String.format("restaurant-service add() invoked: %s for %s", restaurantService.getClass().getName(), restaurantVO.getName()); 

        Restaurant restaurant = new Restaurant(null, null, null); 
        BeanUtils.copyProperties(restaurantVO, restaurant); 
        try { 
            restaurantService.add(restaurant); 
        } catch (Exception ex) { 
            logger.log(Level.WARNING, "Exception raised add Restaurant REST Call "+ ex); 
            return new ResponseEntity<Restaurant>(HttpStatus.UNPROCESSABLE_ENTITY); 
        } 
        return new ResponseEntity<Restaurant>(HttpStatus.CREATED); 
    } 
} 
```

# 服务类

`RestaurantController`类使用了`RestaurantService`接口。`RestaurantService`是一个定义了 CRUD 和一些搜索操作的接口，具体定义如下：

```java
public interface RestaurantService { 

    public void add(Restaurant restaurant) throws Exception; 

    public void update(Restaurant restaurant) throws Exception; 

    public void delete(String id) throws Exception; 

    public Entity findById(String restaurantId) throws Exception; 

    public Collection<Restaurant> findByName(String name) throws Exception; 

    public Collection<Restaurant> findByCriteria(Map<String, ArrayList<String>> name) throws Exception; 
}
```

现在，我们可以实现我们刚刚定义的`RestaurantService`。它还扩展了你在上一章创建的`BaseService`类。我们使用`@Service` Spring 注解将其定义为服务：

```java
@Service("restaurantService") 
public class RestaurantServiceImpl extends BaseService<Restaurant, String> 
        implements RestaurantService { 

    private RestaurantRepository<Restaurant, String> restaurantRepository; 

    @Autowired 
    public RestaurantServiceImpl(RestaurantRepository<Restaurant, String> restaurantRepository) { 
        super(restaurantRepository); 
        this.restaurantRepository = restaurantRepository; 
    } 

    public void add(Restaurant restaurant) throws Exception { 
        if (restaurant.getName() == null || "".equals(restaurant.getName())) { 
            throw new Exception("Restaurant name cannot be null or empty string."); 
        } 

        if (restaurantRepository.containsName(restaurant.getName())) { 
            throw new Exception(String.format("There is already a product with the name - %s", restaurant.getName())); 
        } 

        super.add(restaurant); 
    } 

    @Override 
    public Collection<Restaurant> findByName(String name) throws Exception { 
        return restaurantRepository.findByName(name); 
    } 

    @Override 
    public void update(Restaurant restaurant) throws Exception { 
        restaurantRepository.update(restaurant); 
    } 

    @Override 
    public void delete(String id) throws Exception { 
        restaurantRepository.remove(id); 
    } 

    @Override 
    public Entity findById(String restaurantId) throws Exception { 
        return restaurantRepository.get(restaurantId); 
    } 

    @Override 
    public Collection<Restaurant> findByCriteria(Map<String, ArrayList<String>> name) throws Exception { 
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates. 
    } 
} 
```

# 仓库类

`RestaurantRepository`接口定义了两个新方法：`containsName`和`findByName`方法。它还扩展了`Repository`接口：

```java
public interface RestaurantRepository<Restaurant, String> extends Repository<Restaurant, String> { 

    boolean containsName(String name) throws Exception; 

    Collection<Restaurant> findByName(String name) throws Exception; 
} 
```

`Repository`接口定义了`add`、`remove`和`update`三个方法。它还扩展了`ReadOnlyRepository`接口：

```java
public interface Repository<TE, T> extends ReadOnlyRepository<TE, T> { 

    void add(TE entity); 

    void remove(T id); 

    void update(TE entity); 
} 
```

`ReadOnlyRepository`接口定义了`get`和`getAll`方法，分别返回布尔值、实体和实体集合。如果你想要只暴露仓库的只读抽象，这个接口很有用：

```java
public interface ReadOnlyRepository<TE, T> { 

    boolean contains(T id); 

    Entity get(T id); 

    Collection<TE> getAll(); 
} 
```

Spring 框架使用`@Repository`注解来定义实现仓库的仓库 bean。在`RestaurantRepository`的情况下，可以看到使用了映射来代替实际的数据库实现。这使得所有实体都只保存在内存中。因此，当我们启动服务时，只在内存中找到两家餐厅。我们可以使用 JPA 进行数据库持久化。这是生产就绪实现的一般做法：

```java
@Repository("restaurantRepository") 
public class InMemRestaurantRepository implements RestaurantRepository<Restaurant, String> { 
    private Map<String, Restaurant> entities; 

    public InMemRestaurantRepository() { 
        entities = new HashMap(); 
        Restaurant restaurant = new Restaurant("Big-O Restaurant", "1", null); 
        entities.put("1", restaurant); 
        restaurant = new Restaurant("O Restaurant", "2", null); 
        entities.put("2", restaurant); 
    } 

    @Override 
    public boolean containsName(String name) { 
        try { 
            return this.findByName(name).size() > 0; 
        } catch (Exception ex) { 
            //Exception Handler 
        } 
        return false; 
    } 

    @Override 
    public void add(Restaurant entity) { 
        entities.put(entity.getId(), entity); 
    } 

    @Override 
    public void remove(String id) { 
        if (entities.containsKey(id)) { 
            entities.remove(id); 
        } 
    } 

    @Override 
    public void update(Restaurant entity) { 
        if (entities.containsKey(entity.getId())) { 
            entities.put(entity.getId(), entity); 
        } 
    } 

    @Override 
    public Collection<Restaurant> findByName(String name) throws Exception { 
        Collection<Restaurant> restaurants = new ArrayList<>(); 
        int noOfChars = name.length(); 
        entities.forEach((k, v) -> { 
            if (v.getName().toLowerCase().contains(name.subSequence(0, noOfChars))) { 
                restaurants.add(v); 
            } 
        }); 
        return restaurants; 
    } 

    @Override 
    public boolean contains(String id) { 
        throw new UnsupportedOperationException("Not supported yet.");  
    } 

    @Override 
    public Entity get(String id) { 
        return entities.get(id); 
    } 

    @Override 
    public Collection<Restaurant> getAll() { 
        return entities.values(); 
    } 
} 
```

# 实体类

以下是如何定义扩展了`BaseEntity`的`Restaurant`实体的：

```java
public class Restaurant extends BaseEntity<String> { 

    private List<Table> tables = new ArrayList<>(); 

    public Restaurant(String name, String id, List<Table> tables) { 
        super(id, name); 
        this.tables = tables; 
    } 

    public void setTables(List<Table> tables) { 
        this.tables = tables; 
    } 

    public List<Table> getTables() { 
        return tables; 
    } 

    @Override 
    public String toString() { 
        return String.format("{id: %s, name: %s, address: %s, tables: %s}", this.getId(), 
                         this.getName(), this.getAddress(), this.getTables()); 
    } 

} 
```

由于我们使用 POJO 类来定义实体，在许多情况下我们不需要创建一个 VO。这个想法是对象的状态不应该被持久化。

以下是如何定义扩展了`BaseEntity`的`Table`实体：

```java
public class Table extends BaseEntity<BigInteger> { 

    private int capacity; 

    public Table(String name, BigInteger id, int capacity) { 
        super(id, name); 
        this.capacity = capacity; 
    } 

    public void setCapacity(int capacity) { 
        this.capacity = capacity; 
    } 

    public int getCapacity() { 
        return capacity; 
    } 

    @Override 
    public String toString() { 
        return String.format("{id: %s, name: %s, capacity: %s}", 
                         this.getId(), this.getName(), this.getCapacity());    } 

} 
```

以下是如何定义`Entity`抽象类的：

```java
public abstract class Entity<T> { 

    T id; 
    String name; 

    public T getId() { 
        return id; 
    } 

    public void setId(T id) { 
        this.id = id; 
    } 

    public String getName() { 
        return name; 
    } 

    public void setName(String name) { 
        this.name = name; 
    } 

} 
```

以下是如何定义`BaseEntity`抽象类的。它扩展了`Entity`

抽象类：

```java
public abstract class BaseEntity<T> extends Entity<T> { 

    private T id; 
    private boolean isModified; 
    private String name; 

    public BaseEntity(T id, String name) { 
        this.id = id; 
        this.name = name; 
    } 

    public T getId() { 
        return id; 
    } 

    public void setId(T id) { 
        this.id = id; 
    } 

    public boolean isIsModified() { 
        return isModified; 
    } 

    public void setIsModified(boolean isModified) { 
        this.isModified = isModified; 
    } 

    public String getName() { 
        return name; 
    } 

    public void setName(String name) { 
        this.name = name; 
    } 

} 
```

我们已经完成了 Restaurant 服务的实现。现在，我们将开发 Eureka 模块（服务）。

# 注册和发现服务（Eureka 服务）

我们需要一个所有微服务都可以注册和引用的地方——一个服务发现和注册应用程序。Spring Cloud 提供了最先进的服务注册和发现应用程序 Netflix Eureka。我们将利用它为我们的示例项目 OTRS 服务。

一旦您按照本节中的描述配置了 Eureka 服务，它将可供所有传入请求使用以在 Eureka 服务上列出它。Eureka 服务注册/列出通过 Eureka 客户端配置的所有微服务。一旦您启动您的服务，它就会通过`application.yml`中配置的 Eureka 服务发送 ping，一旦建立连接，Eureka 服务将注册该服务。

它还通过统一的连接方式启用微服务的发现。您不需要任何 IP、主机名或端口来查找服务，您只需要提供服务 ID 即可。服务 ID 在各个微服务的`application.yml`中配置。

在以下三个步骤中，我们可以创建一个 Eureka 服务（服务注册和发现服务）：

1.  **Maven 依赖**：它需要一个 Spring Cloud 依赖，如图所示，并在`pom.xml`中的启动类中使用`@EnableEurekaApplication`注解：

```java
<dependency> 
      <groupId>org.springframework.cloud</groupId> 
      <artifactId>spring-cloud-starter-config</artifactId> 
</dependency> 
<dependency> 
      <groupId>org.springframework.cloud</groupId> 
      <artifactId>spring-cloud-netflix-eureka-server</artifactId> 
</dependency> 
```

1.  **启动类**：启动类`App`通过仅使用`@EnableEurekaApplication`类注解来无缝运行 Eureka 服务：

```java
package com.packtpub.mmj.eureka.service; 

import org.springframework.boot.SpringApplication; 
import org.springframework.boot.autoconfigure.SpringBootApplication; 
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer; 

@SpringBootApplication 
@EnableEurekaServer 
public class App { 

    public static void main(String[] args) { 
        SpringApplication.run(App.class, args); 
    } 
} 
```

在`pom.xml`项目的`<properties>`标签下使用`<start-class>com.packtpub.mmj.eureka.service.App</start-class>`。

1.  **Spring 配置**：Eureka 服务也需要以下 Spring 配置来实现 Eureka 服务器的配置（`src/main/resources/application.yml`）：

```java
server: 
  port: 8761  # HTTP port 

eureka: 
  instance: 
    hostname: localhost 
  client: 
    registerWithEureka: false 
    fetchRegistry: false 
    serviceUrl: 
        defaultZone: ${vcap.services.${PREFIX:}eureka.credentials.uri:http://user:password@localhost:8761}/eureka/ 
  server: 
    waitTimeInMsWhenSyncEmpty: 0 
    enableSelfPreservation: false 

```

# **Eureka 客户端**

与 Eureka 服务器类似，每个 OTRS 服务也应该包含 Eureka 客户端配置，以便可以建立 Eureka 服务器和客户端之间的连接。没有这个，服务的注册和发现是不可能的。

您的服务可以使用以下 Spring 配置来配置 Eureka 客户端。在`restaurant-service\src\main\resources\application.yml`中添加以下配置：

```java
eureka: 
  client: 
    serviceUrl: 
      defaultZone: http://localhost:8761/eureka/ 
```

# 预订和用户服务

我们可以使用`RestaurantService`实现来开发预订和用户服务。用户服务可以提供与用户资源相关的 CRUD 操作端点。预订服务可以提供与预订资源相关的 CRUD 操作端点和桌位可用性。您可以在 Packt 网站或 Packt Publishing GitHub 仓库上找到这些服务的示例代码。

# 执行

要了解我们的代码是如何工作的，我们首先需要构建它，然后执行它。我们将使用 Maven 清理包来构建服务 JAR。

现在，要执行这些服务 JAR，只需从项目根目录执行以下命令即可：

```java
java -jar <service>/target/<service_jar_file> 
```

以下是一些示例：

```java
java -jar restaurant-service/target/restaurant-service.jar 
java -jar eureka-service/target/eureka-service.jar 
```

我们将按以下顺序从项目根目录执行我们的服务。首先应启动 Eureka 服务；最后三个微服务的顺序可以改变：

```java
java -jar eureka-service/target/eureka-service.jar
java -jar restaurant-service/target/restaurant-service.jar java -jar booking-service/target/booking-service.jar java -jar user-service/target/user-service.jar
```

# 测试

为了启用测试，在`pom.xml`文件中添加以下依赖项：

```java
<dependency> 
    <groupId>org.springframework.boot</groupId> 
    <artifactId>spring-boot-starter-test</artifactId> 
</dependency> 
```

为了测试`RestaurantController`，已添加以下文件：

+   `RestaurantControllerIntegrationTests`类，它使用了

    `@SpringApplicationConfiguration`注解以选择 Spring Boot 使用的相同配置：

```java
@RunWith(SpringJUnit4ClassRunner.class) 
@SpringApplicationConfiguration(classes = RestaurantApp.class) 
public class RestaurantControllerIntegrationTests extends 
        AbstractRestaurantControllerTests { 

}
```

+   一个`abstract`类来编写我们的测试：

```java
public abstract class AbstractRestaurantControllerTests { 

    protected static final String RESTAURANT = "1"; 
    protected static final String RESTAURANT_NAME = "Big-O Restaurant"; 

    @Autowired 
    RestaurantController restaurantController; 

    @Test 
    public void validResturantById() { 
        Logger.getGlobal().info("Start validResturantById test"); 
        ResponseEntity<Entity> restaurant = restaurantController.findById(RESTAURANT); 

        Assert.assertEquals(HttpStatus.OK, restaurant.getStatusCode()); 
        Assert.assertTrue(restaurant.hasBody()); 
        Assert.assertNotNull(restaurant.getBody()); 
        Assert.assertEquals(RESTAURANT, restaurant.getBody().getId()); 
        Assert.assertEquals(RESTAURANT_NAME, restaurant.getBody().getName()); 
        Logger.getGlobal().info("End validResturantById test"); 
    } 

    @Test 
    public void validResturantByName() { 
        Logger.getGlobal().info("Start validResturantByName test"); 
        ResponseEntity<Collection<Restaurant>> restaurants = restaurantController.findByName(RESTAURANT_NAME); 
        Logger.getGlobal().info("In validAccount test"); 

        Assert.assertEquals(HttpStatus.OK, restaurants.getStatusCode()); 
        Assert.assertTrue(restaurants.hasBody()); 
        Assert.assertNotNull(restaurants.getBody()); 
        Assert.assertFalse(restaurants.getBody().isEmpty()); 
        Restaurant restaurant = (Restaurant) restaurants.getBody().toArray()[0]; 
        Assert.assertEquals(RESTAURANT, restaurant.getId()); 
        Assert.assertEquals(RESTAURANT_NAME, restaurant.getName()); 
        Logger.getGlobal().info("End validResturantByName test"); 
    } 

    @Test 
    public void validAdd() { 
        Logger.getGlobal().info("Start validAdd test"); 
        RestaurantVO restaurant = new RestaurantVO(); 
        restaurant.setId("999"); 
        restaurant.setName("Test Restaurant"); 

        ResponseEntity<Restaurant> restaurants = restaurantController.add(restaurant); 
        Assert.assertEquals(HttpStatus.CREATED, restaurants.getStatusCode()); 
        Logger.getGlobal().info("End validAdd test"); 
    } 
} 
```

+   最后是`RestaurantControllerTests`类，它扩展了之前创建的`abstract`类，还创建了`RestaurantService`和`RestaurantRepository`实现：

```java
public class RestaurantControllerTests extends AbstractRestaurantControllerTests { 

    protected static final Restaurant restaurantStaticInstance = new Restaurant(RESTAURANT, 
            RESTAURANT_NAME, null); 

    protected static class TestRestaurantRepository implements RestaurantRepository<Restaurant, String> { 

        private Map<String, Restaurant> entities; 

        public TestRestaurantRepository() { 
            entities = new HashMap(); 
            Restaurant restaurant = new Restaurant("Big-O Restaurant", "1", null); 
            entities.put("1", restaurant); 
            restaurant = new Restaurant("O Restaurant", "2", null); 
            entities.put("2", restaurant); 
        } 

        @Override 
        public boolean containsName(String name) { 
            try { 
                return this.findByName(name).size() > 0; 
            } catch (Exception ex) { 
                //Exception Handler 
            } 
            return false; 
        } 

        @Override 
        public void add(Restaurant entity) { 
            entities.put(entity.getId(), entity); 
        } 

        @Override 
        public void remove(String id) { 
            if (entities.containsKey(id)) { 
                entities.remove(id); 
            } 
        } 

        @Override 
        public void update(Restaurant entity) { 
            if (entities.containsKey(entity.getId())) { 
                entities.put(entity.getId(), entity); 
            } 
        } 

        @Override 
        public Collection<Restaurant> findByName(String name) throws Exception { 
            Collection<Restaurant> restaurants = new ArrayList(); 
            int noOfChars = name.length(); 
            entities.forEach((k, v) -> { 
                if (v.getName().toLowerCase().contains(name.subSequence(0, noOfChars))) { 
                    restaurants.add(v); 
                } 
            }); 
            return restaurants; 
        } 

        @Override 
        public boolean contains(String id) { 
            throw new UnsupportedOperationException("Not supported yet.");
        } 

        @Override 
        public Entity get(String id) { 
            return entities.get(id); 
        } 
        @Override 
        public Collection<Restaurant> getAll() { 
            return entities.values(); 
        } 
    } 

    protected TestRestaurantRepository testRestaurantRepository = new TestRestaurantRepository(); 
    protected RestaurantService restaurantService = new RestaurantServiceImpl(testRestaurantRepository); 

    @Before 
    public void setup() { 
        restaurantController = new RestaurantController(restaurantService); 

    } 
} 
```

# 参考文献

+   《RESTful Java Patterns and Best Practices》by Bhakti Mehta, Packt Publishing: [`www.packtpub.com/application-development/restful-java-patterns-and-best-practices`](https://www.packtpub.com/application-development/restful-java-patterns-and-best-practices)

+   Spring Cloud: [`cloud.spring.io/`](http://cloud.spring.io/)

+   Netflix Eureka: [`github.com/netflix/eureka`](https://github.com/netflix/eureka)

# 总结

在本章中，我们学习了领域驱动设计模型如何在微服务中使用。运行演示应用程序后，我们可以看到每个微服务如何可以独立地开发、部署和测试。你可以使用 Spring Cloud 非常容易地创建微服务。我们还探讨了如何使用 Spring Cloud 与 Eureka 注册和发现组件。

在下一章中，我们将学习如何将微服务部署在容器中，例如 Docker。我们还将了解使用 REST Java 客户端和其他工具进行微服务测试。


# 第五章：部署和测试

在本章中，我们将接着第四章《实现微服务》的内容继续讲解。我们将向仅依赖于三个功能性服务（餐厅、用户和预订服务）以及 Eureka（服务发现和注册）的在线桌位预订系统（OTRS）应用程序添加一些更多服务，以创建一个完全功能的微服务堆栈。这个堆栈将包括网关（Zuul）、负载均衡（Ribbon 与 Zuul 和 Eureka）、监控（Hystrix、Turbine 和 Hystrix 仪表板）。你希望拥有组合 API，并了解一个微服务如何与其他微服务通信。本章还将解释如何使用 Docker 容器化微服务，以及如何使用`docker-compose`一起运行多个容器。在此基础上，我们还将添加集成测试。

在本章中，我们将介绍以下主题：

+   使用 Netflix OSS 的微服务架构概述

+   边缘服务器

+   负载均衡微服务

+   断路器和监控

+   使用容器部署微服务

+   使用 Docker 容器进行微服务集成测试

# 良好的微服务所需的强制服务

为了实现基于微服务的架构设计，应该有一些模式/服务需要到位。这个列表包括以下内容：

+   服务发现和注册

+   边缘或代理服务器

+   负载均衡

+   断路器

+   监控

我们将在本章实现这些服务，以完成我们的 OTRS 系统。以下是简要概述。我们稍后详细讨论这些模式/服务。

# 服务发现和注册

Netflix Eureka 服务器用于服务发现和注册。我们在上一章创建了 Eureka 服务。它不仅允许你注册和发现服务，还提供使用 Ribbon 的负载均衡。

# 边缘服务器

边缘服务器提供一个单一的访问点，允许外部世界与你的系统交互。你的所有 API 和前端都只能通过这个服务器访问。因此，这些也被称为网关或代理服务器。这些被配置为将请求路由到不同的微服务或前端应用程序。在 OTRS 应用程序中，我们将使用 Netflix Zuul 服务器作为边缘服务器。

# 负载均衡

Netflix Ribbon 用于负载均衡。它与 Zuul 和 Eureka 服务集成，为内部和外部调用提供负载均衡。

# 断路器

一个故障或断裂不应该阻止你的整个系统运行。此外，一个服务或 API 的反复失败应该得到适当的处理。断路器提供了这些功能。Netflix Hystrix 作为断路器使用，有助于保持系统运行。

# 监控

使用 Netflix Hystrix 仪表板和 Netflix Turbine 进行微服务监控。它提供了一个仪表板，用于检查运行中微服务的状态。

# 使用 Netflix OSS 的微服务架构概述

Netflix 是微服务架构的先驱。他们是第一个成功在大规模实施微服务架构的人。他们还通过将大部分微服务工具开源，并命名为 Netflix **开源软件中心**（**OSS**），极大地提高了微服务的普及程度并做出了巨大贡献。

根据 Netflix 的博客，当 Netflix 开发他们的平台时，他们使用了 Apache Cassandra 进行数据存储，这是一个来自 Apache 的开源工具。他们开始通过修复和优化扩展为 Cassandra 做贡献。这导致了 Netflix 看到将 Netflix 项目以 OSS 的名义发布的益处。

Spring 抓住了机会，将许多 Netflix 的开源项目（如 Zuul、Ribbon、Hystrix、Eureka 服务器和 Turbine）集成到 Spring Cloud 中。这是 Spring Cloud 能够为生产就绪的微服务提供现成平台的原因之一。

现在，让我们来看看几个重要的 Netflix 工具以及它们如何在微服务架构中发挥作用：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/451c2530-d3dd-4dca-ab1e-04a6f2c8c0a0.jpg)

微服务架构图

正如您在前面的图表中所看到的，对于每一种微服务实践，我们都有一个与之相关的 Netflix 工具。我们可以通过以下映射来了解它。详细信息在本章的相应部分中介绍，关于 Eureka 的部分在最后一章中有详细说明：

+   **边缘服务器**：我们使用 Netflix Zuul 服务器作为边缘服务器。

+   **负载均衡**：Netflix Ribbon 用于负载均衡。

+   **断路器**：Netflix Hystrix 用作断路器，有助于保持系统运行。

+   **服务发现与注册**：Netflix Eureka 服务器用于服务发现和注册。

+   **监控仪表板**：Hystrix 监控仪表板与 Netflix Turbine 配合使用，用于微服务监控。它提供了一个仪表板，用于检查运行中微服务的状态。

# 负载均衡

负载均衡是服务于请求的方式，以最大化速度和容量利用率，并确保没有服务器因请求过多而超载。负载均衡器还将请求重定向到其他主机服务器，如果服务器宕机的话。在微服务架构中，微服务可以服务于内部或外部请求。基于这一点，我们可以有两种类型的负载均衡——客户端负载均衡和服务器端负载均衡。

# 服务器端负载均衡

我们将讨论服务器端负载均衡；在那之前，我们先讨论路由。从微服务架构的角度来看，为我们的 OTRS 应用程序定义路由机制是很重要的。例如，`/`（根）可以映射到我们的 UI 应用程序。同样，`/restaurantapi`和`/userapi`可以分别映射到餐厅服务和用户服务。边缘服务器也执行带有负载均衡的路由。

我们将使用 Netflix Zuul 服务器作为我们的边缘服务器。Zuul 是一个基于 JVM 的路由和服务器端负载均衡器。Zuul 支持用任何 JVM 语言编写规则和过滤器，并内置了对 Java 和 Groovy 的支持。

Netflix Zuul 默认具有发现客户端（Eureka 客户端）支持。Zuul 还利用 Ribbon 和 Eureka 进行负载均衡。

外部世界（UI 和其他客户端）调用边缘服务器，使用`application.yml`中定义的路线调用内部服务并提供响应。如果您认为它充当代理服务器，为内部网络承担网关责任，并且为定义和配置的路线调用内部服务，那么您的猜测是正确的。

通常，建议对所有请求使用单个边缘服务器。然而，一些公司为了扩展，每个客户端使用一个边缘服务器。例如，Netflix 为每种设备类型使用一个专用的边缘服务器。

在下一章中，我们配置和实现微服务安全时，也将使用边缘服务器。

在 Spring Cloud 中配置和使用边缘服务器相当简单。您需要执行以下步骤：

1.  在`pom.xml`文件中定义 Zuul 服务器依赖项：

```java
<dependency> 
      <groupId>org.springframework.cloud</groupId> 
      <artifactId>spring-cloud-starter-zuul</artifactId> 
</dependency> 
```

1.  在您的应用程序类中使用`@EnableZuulProxy`注解。它还内部使用`@EnableDiscoveryClient`注解；因此，它也会自动注册到 Eureka 服务器。您可以在*客户端负载均衡部分*的图中找到注册的 Zuul 服务器。

1.  更新`application.yml`文件中的 Zuul 配置，如下所示：

+   `zuul:ignoredServices`：这跳过了服务的自动添加。我们可以在这里定义服务 ID 模式。`*`表示我们忽略所有服务。在下面的示例中，除了`restaurant-service`，所有服务都被忽略。

+   `Zuul.routes`：这包含定义 URI 模式的`path`属性。在这里，`/restaurantapi`通过`serviceId`属性映射到`restaurant-service`。`serviceId`属性代表 Eureka 服务器中的服务。如果未使用 Eureka 服务器，可以使用 URL 代替服务。我们还使用了`stripPrefix`属性来去除前缀（`/restaurantapi`），结果`/restaurantapi/v1/restaurants/1`调用转换为在调用服务时`/v1/restaurants/1`:

```java
application.yml 
info: 
    component: Zuul Server 
# Spring properties 
spring: 
  application: 
     name: zuul-server  # Service registers under this name 

endpoints: 
    restart: 
        enabled: true 
    shutdown: 
        enabled: true 
    health: 
        sensitive: false 

zuul: 
    ignoredServices: "*" 
    routes: 
        restaurantapi: 
            path: /restaurantapi/** 
            serviceId: restaurant-service 
            stripPrefix: true 

server: 
    port: 8765 

# Discovery Server Access 
eureka: 
  instance: 
    leaseRenewalIntervalInSeconds: 3 
    metadataMap: 
      instanceId: ${vcap.application.instance_id:${spring.application.name}:${spring.application.instance_id:${random.value}}} 
    serviceUrl: 
      defaultZone: http://localhost:8761/eureka/ 
    fetchRegistry: false 
```

请注意，Eureka 应用程序只在每台主机上注册任何服务的单个实例。您需要为`metadataMap.instanceid`使用以下值，以便在同一台主机上注册同一应用程序的多个实例，以便负载均衡工作：

`${spring.application.name}:${vcap.application.instance_id:${spring.application.instance_id:${random.value}}}`

让我们看看一个工作的边缘服务器。首先，我们将按照以下方式调用端口`3402`上部署的餐厅服务：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/96fe451a-e8c4-48fc-b80a-a09784c1795b.png)

直接调用餐厅服务

然后，我们将使用部署在端口`8765`的边缘服务器调用同一服务。你可以看到，调用`/v1/restaurants?name=o`时使用了`/restaurantapi`前缀，并且给出了相同的结果：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/6202f3a7-e83f-4f7f-a992-5f153e395f66.png)

使用边缘服务器调用餐厅服务

# 客户端负载均衡

微服务需要进程间通信，以便服务能够相互通信。Spring Cloud 使用 Netflix Ribbon，这是一个客户端负载均衡器，扮演着这一关键角色，并可以处理 HTTP 和 TCP。Ribbon 是云兼容的，并提供了内置的故障弹性。Ribbon 还允许你使用多个可插拔的负载均衡规则。它将客户端与负载均衡器集成在一起。

在上一章中，我们添加了 Eureka 服务器。Spring Cloud 默认通过 Ribbon 与 Eureka 服务器集成。这种集成提供了以下功能：

+   当使用 Eureka 服务器时，你不需要硬编码远程服务器 URL 进行发现。这是一个显著的优势，尽管如果你需要，你仍然可以使用`application.yml`文件中配置的服务器列表（`listOfServers`）。

+   服务器列表从 Eureka 服务器获取。Eureka 服务器用`DiscoveryEnabledNIWSServerList`接口覆盖了`ribbonServerList`。

+   查找服务器是否运行的请求被委托给 Eureka。这里使用了`DiscoveryEnabledNIWSServerList`接口来代替 Ribbon 的`IPing`。

在 Spring Cloud 中，使用 Ribbon 有不同的客户端可供选择，比如`RestTemplate`或`FeignClient`。这些客户端使得微服务之间能够相互通信。当使用 Eureka 服务器时，客户端使用实例 ID 代替主机名和端口来对服务实例进行 HTTP 调用。客户端将服务 ID 传递给 Ribbon，然后 Ribbon 使用负载均衡器从 Eureka 服务器中选择实例。

如以下屏幕截图所示，如果 Eureka 中有多个服务实例可用，Ribbon 根据负载均衡算法只为请求选择一个：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/ff86c7a3-c57c-4228-b6a2-5b87de6eacea.png)

多服务注册 - 餐厅服务

我们可以使用`DiscoveryClient`来查找 Eureka 服务器中所有可用的服务实例，如下面的代码所示。`DiscoveryClientSample`类中的`getLocalServiceInstance()`方法返回 Eureka 服务器中所有可用的本地服务实例。

这是一个`DiscoveryClient`示例：

```java
@Component 
class DiscoveryClientSample implements CommandLineRunner { 

    @Autowired 
    private DiscoveryClient; 

    @Override 
    public void run(String... strings) throws Exception { 
        // print the Discovery Client Description 
        System.out.println(discoveryClient.description()); 
        // Get restaurant-service instances and prints its info 
        discoveryClient.getInstances("restaurant-service").forEach((ServiceInstance serviceInstance) -> { 
            System.out.println(new StringBuilder("Instance --> ").append(serviceInstance.getServiceId()) 
                    .append("\nServer: ").append(serviceInstance.getHost()).append(":").append(serviceInstance.getPort()) 
                    .append("\nURI: ").append(serviceInstance.getUri()).append("\n\n\n")); 
        }); 
    } 
} 
```

当执行此代码时，它会打印以下信息。它显示了餐厅服务的两个实例：

```java
Spring Cloud Eureka Discovery Client 
Instance: RESTAURANT-SERVICE 
Server: SOUSHARM-IN:3402 
URI: http://SOUSHARM-IN:3402 
Instance --> RESTAURANT-SERVICE 
Server: SOUSHARM-IN:3368 
URI: http://SOUSHARM-IN:3368 
```

下面的示例展示了这些客户端如何使用。你可以在两个客户端中看到，服务名称`restaurant-service`被用来代替服务主机名和端口。这些客户端调用`/v1/restaurants`来获取包含在名称查询参数中的餐厅名称的餐厅列表。

这是一个`RestTemplate`示例：

```java
@Component
class RestTemplateExample implements CommandLineRunner {
  @Autowired
  private RestTemplate restTemplate;
  @Override
  public void run(String... strings) throws Exception {
    System.out.println("\n\n\n start RestTemplate client...");
    ResponseEntity<Collection<Restaurant>> exchange
    = this.restTemplate.exchange(
    "http://restaurant-service/v1/restaurants?name=o",
    HttpMethod.GET,
    null,
    new ParameterizedTypeReference<Collection<Restaurant>>() {
    },
    (Object) "restaurants");
    exchange.getBody().forEach((Restaurant restaurant) -> {
      System.out.println("\n\n\n[ " + restaurant.getId() + " " +  restaurant.getName() + "]");
      });
   }
}
```

这是一个`FeignClient`示例：

```java
@FeignClient("restaurant-service")
interface RestaurantClient {
  @RequestMapping(method = RequestMethod.GET, value =  "/v1/restaurants")
  Collection<Restaurant> getRestaurants(@RequestParam("name") String name);
  }
@Component
class FeignSample implements CommandLineRunner {
  @Autowired
  private RestaurantClient restaurantClient;
  @Override
  public void run(String... strings) throws Exception {
    this.restaurantClient.getRestaurants("o").forEach((Restaurant     restaurant) -> {
      System.out.println("\n\n\n[ " + restaurant.getId() + " " +  restaurant.getName() + "]");
      });
    }
} 
```

所有前面的示例都将打印以下输出：

```java
[ 1 Big-O Restaurant] 
[ 2 O Restaurant] 
```

为了演示目的，我们在边缘应用程序主类 Java 文件中添加了所有客户端—`discovery`客户端、`RestTemplate`客户端和`FeignClient`。由于我们所有这些客户端都实现了`CommandLineRunner`接口，这会在边缘应用程序服务启动后立即执行。

# 断路器与监控

通常而言，断路器是一种*自动装置，用于在电气电路中作为安全措施停止电流的流动*。

同样的概念也用于微服务开发，称为**断路器**设计模式。它跟踪外部服务的可用性，如 Eureka 服务器、API 服务如`restaurant-service`等，并防止服务消费者对任何不可用的服务执行任何操作。

这是微服务架构的另一个重要方面，一种安全措施

（安全机制）当服务消费者对服务的调用没有响应时，这称为断路器。

我们将使用 Netflix Hystrix 作为断路器。当发生故障时（例如，由于通信错误或超时），它在服务消费者内部调用回退方法。它在服务消费者内执行。在下一节中，您将找到实现此功能的代码。

Hystrix 在服务未能响应时打开电路，并在服务再次可用之前快速失败。当对特定服务的调用达到一定阈值（默认阈值是五秒内 20 次失败），电路打开，调用不再进行。您可能想知道，如果 Hystrix 打开电路，那么它是如何知道服务可用的？它异常地允许一些请求调用服务。

# 使用 Hystrix 的回退方法

实现回退方法有五个步骤。为此，我们将创建另一个服务，`api-service`，就像我们创建其他服务一样。`api-service`服务将消费其他服务，如`restaurant-service`等，并将在边缘服务器中配置以对外暴露 OTRS API。这五个步骤如下：

1.  **启用断路器**：主要消费其他服务的微服务类应该用`@EnableCircuitBreaker`注解标记。因此，我们将注释`src\main\java\com\packtpub\mmj\api\service\ApiApp.java`：

```java
@SpringBootApplication 
@EnableCircuitBreaker 
@ComponentScan({"com.packtpub.mmj.user.service", "com.packtpub.mmj.common"}) 
public class ApiApp { 
```

1.  **配置回退方法**：用`@HystrixCommand`注解来配置`fallbackMethod`。我们将注释控制器方法来配置回退方法。这是文件：`src\main\java\com\packtpub\mmj\api\service\restaurant\RestaurantServiceAPI.java`：

```java
@HystrixCommand(fallbackMethod = "defaultRestaurant") 
    @RequestMapping("/restaurants/{restaurant-id}") 
    @HystrixCommand(fallbackMethod = "defaultRestaurant") 
    public ResponseEntity<Restaurant> getRestaurant( 
            @PathVariable("restaurant-id") int restaurantId) { 
        MDC.put("restaurantId", restaurantId); 
        String url = "http://restaurant-service/v1/restaurants/" + restaurantId; 
        LOG.debug("GetRestaurant from URL: {}", url); 

        ResponseEntity<Restaurant> result = restTemplate.getForEntity(url, Restaurant.class); 
        LOG.info("GetRestaurant http-status: {}", result.getStatusCode()); 
        LOG.debug("GetRestaurant body: {}", result.getBody()); 

        return serviceHelper.createOkResponse(result.getBody()); 
    }  
```

1.  **定义回退方法**：处理失败并执行安全步骤的方法。在这里，我们只是添加了一个示例；这可以根据我们想要处理失败的方式进行修改：

```java
public ResponseEntity<Restaurant> defaultRestaurant(
@PathVariable int restaurantId) { 
  return serviceHelper.createResponse(null, HttpStatus.BAD_GATEWAY); 
  } 
```

1.  **Maven 依赖项**：我们需要在`pom.xml`中为 API 服务或希望确保 API 调用的项目中添加以下依赖项：

```java
<dependency> 
    <groupId>org.springframework.cloud</groupId> 
    <artifactId>spring-cloud-starter-hystrix</artifactId> 
</dependency> 
```

1.  **在`application.yml`中配置 Hystrix**：我们将在我们的`application.yml`文件中添加以下 Hystrix 属性：

```java
       hystrix: 
  threadpool: 
    default: 
      # Maximum number of concurrent requests when using thread pools (Default: 10) 
      coreSize: 100 
      # Maximum LinkedBlockingQueue size - -1 for using SynchronousQueue (Default: -1) 
      maxQueueSize: -1 
      # Queue size rejection threshold (Default: 5) 
      queueSizeRejectionThreshold: 5 
  command: 
    default: 
      circuitBreaker: 
        sleepWindowInMilliseconds: 30000 
        requestVolumeThreshold: 2 
      execution: 
        isolation: 
#          strategy: SEMAPHORE, no thread pool but timeout handling stops to work 
          strategy: THREAD 
          thread: 
            timeoutInMilliseconds: 6000
```

这些步骤应该足以确保服务调用的安全，并向服务消费者返回一个更合适的响应。

# 监控

Hystrix 提供了一个带有 web UI 的仪表板，提供很好的电路断路器图形：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/88b20511-ffd5-4562-979d-50210d86d46c.jpg)

默认的 Hystrix 仪表板

Netflix Turbine 是一个 web 应用程序，它连接到 Hystrix 应用程序集群的实例并聚合信息，实时进行（每 0.5 秒更新一次）。Turbine 使用称为 Turbine 流的流提供信息。

如果你将 Hystrix 与 Netflix Turbine 结合使用，那么你可以在 Hystrix 仪表板上获取 Eureka 服务器上的所有信息。这为你提供了有关所有电路断路器的信息的全景视图。

要使用 Turbine 和 Hystrix，只需在前面截图中的第一个文本框中输入 Turbine 的 URL`http://localhost:8989/turbine.stream`（在`application.yml`中为 Turbine 服务器配置了端口`8989`），然后点击监控流。

Netflix Hystrix 和 Turbine 使用 RabbitMQ，这是一个开源的消息队列软件。RabbitMQ 基于**高级消息队列协议**（**AMQP**）工作。这是一个软件，在此软件中可以定义队列并由连接的应用程序交换消息。消息可以包含任何类型的信息。消息可以存储在 RabbitMQ 队列中，直到接收应用程序连接并消耗消息（将消息从队列中移除）。

Hystrix 使用 RabbitMQ 将度量数据发送到 Turbine。

在配置 Hystrix 和 Turbine 之前，请在你的平台上演示安装 RabbitMQ 应用程序。Hystrix 和 Turbine 使用 RabbitMQ 彼此之间进行通信。

# 设置 Hystrix 仪表板

我们将在 IDE 中创建另一个项目，以与创建其他服务相同的方式创建 Hystrix 仪表板。在这个新项目中，我们将添加新的 Maven 依赖项`dashboard-server`，用于 Hystrix 服务器。在 Spring Cloud 中配置和使用 Hystrix 仪表板相当简单。

当你运行 Hystrix 仪表板应用程序时，它会看起来像前面所示的默认 Hystrix 仪表板快照。你只需要按照以下步骤操作：

1.  在`pom.xml`文件中定义 Hystrix 仪表板依赖项：

```java
<dependency> 
    <groupId>org.springframework.cloud</groupId> 
    <artifactId>spring-cloud-starter-hystrix-dashboard</artifactId> 
</dependency> 
```

1.  在主 Java 类中的`@EnableHystrixDashboard`注解为您使用它做了所有事情。我们还将使用`@Controller`将根 URI 的请求转发到 Hystrix 仪表板 UI URI（`/hystrix`），如下所示：

```java
@SpringBootApplication 
@Controller 
@EnableHystrixDashboard 
public class DashboardApp extends SpringBootServletInitializer { 

    @RequestMapping("/") 
    public String home() { 
        return "forward:/hystrix"; 
    } 

    @Override 
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) { 
        return application.sources(DashboardApp.class).web(true); 
    } 

    public static void main(String[] args) { 
        SpringApplication.run(DashboardApp.class, args); 
    } 
} 
```

1.  如所示更新`application.yml`中的仪表板应用程序配置：

```java
# Hystrix Dashboard properties 
spring: 
    application: 
        name: dashboard-server 

endpoints: 
    restart: 
        enabled: true 
    shutdown: 
        enabled: true 

server: 
    port: 7979 

eureka: 
    instance: 
        leaseRenewalIntervalInSeconds: 3 
        metadataMap: 
            instanceId: ${vcap.application.instance_id:${spring.application.name}:${spring.application.instance_id:${random.value}}} 

    client: 
        # Default values comes from org.springframework.cloud.netflix.eurek.EurekaClientConfigBean 
        registryFetchIntervalSeconds: 5 
        instanceInfoReplicationIntervalSeconds: 5 
        initialInstanceInfoReplicationIntervalSeconds: 5 
        serviceUrl: 
            defaultZone: http://localhost:8761/eureka/ 
        fetchRegistry: false 

logging: 
    level: 
        ROOT: WARN 
        org.springframework.web: WARN 
```

# 创建 Turbine 服务

Turbine 将所有`/hystrix.stream`端点聚合成一个合并的`/turbine.stream`，以供 Hystrix 仪表板使用，这更有助于查看系统的整体健康状况，而不是使用`/hystrix.stream`监视各个服务。我们将在 IDE 中创建另一个服务项目，然后在`pom.xml`中为 Turbine 添加 Maven 依赖项。

现在，我们将使用以下步骤配置 Turbine 服务器：

1.  在`pom.xml`中定义 Turbine 服务器的依赖项：

```java
<dependency> 
    <groupId> org.springframework.cloud</groupId> 
    <artifactId>spring-cloud-starter-turbine-stream</artifactId> 
</dependency> 
<dependency> 
     <groupId>org.springframework.cloud</groupId> 
     <artifactId>spring-cloud-starter-stream-rabbit</artifactId> 
</dependency> 
<dependency> 
     <groupId>org.springframework.boot</groupId> 
     <artifactId>spring-boot-starter-actuator</artifactId> 
</dependency> 

```

1.  在您的应用程序类中使用`@EnableTurbineStream`注解，如

    此处显示。我们还定义了一个将返回 RabbitMQ `ConnectionFactory`的 Bean：

```java
@SpringBootApplication 
@EnableTurbineStream 
@EnableEurekaClient 
public class TurbineApp { 

    private static final Logger LOG = LoggerFactory.getLogger(TurbineApp.class); 

    @Value("${app.rabbitmq.host:localhost}") 
    String rabbitMQHost; 

    @Bean 
    public ConnectionFactory connectionFactory() { 
        LOG.info("Creating RabbitMQHost ConnectionFactory for host: {}", rabbitMQHost); 
        CachingConnectionFactory cachingConnectionFactory = new CachingConnectionFactory(rabbitMQHost); 
        return cachingConnectionFactory; 
    } 

    public static void main(String[] args) { 
        SpringApplication.run(TurbineApp.class, args); 
    } 
} 
```

1.  根据下面所示，更新`application.yml`中的 Turbine 配置：

+   `server:port`：Turbine HTTP 使用的主要端口

+   `management:port`：Turbine 执行器端点的端口：

```java
application.yml 
spring: 
    application: 
        name: turbine-server 

server: 
    port: 8989 

management: 
    port: 8990 

turbine: 
    aggregator: 
        clusterConfig: USER-SERVICE,RESTAURANT-SERVICE 
    appConfig: user-service,restaurant-service  

eureka: 
    instance: 
        leaseRenewalIntervalInSeconds: 10 
        metadataMap: 
            instanceId: ${vcap.application.instance_id:${spring.application.name}:${spring.application.instance_id:${random.value}}} 
    client: 
        serviceUrl: 
            defaultZone: ${vcap.services.${PREFIX:}eureka.credentials.uri:http://user:password@localhost:8761}/eureka/ 
        fetchRegistry: true 

logging: 
    level: 
        root: INFO 
        com.netflix.discovery: 'OFF' 
        org.springframework.integration: DEBUG 
```

之前，我们使用`turbine.aggregator.clusterConfig`属性将用户和餐厅服务添加到一个集群中。这里，值以大写字母表示，因为 Eureka 以大写字母返回服务名称。而且，`turbine.appConfig`属性包含了 Turbine 用来查找实例的 Eureka 服务 ID 列表。请注意，之前的步骤总是使用默认配置创建了相应的服务器。如有需要，可以使用特定设置覆盖默认配置。

# 构建和运行 OTRS 应用程序

使用以下文件：`..\Chapter5 \pom.xml`，使用`mvn clean install`构建所有项目。

输出应该如下所示：

```java
6392_chapter5 ..................................... SUCCESS [3.037s] 
online-table-reservation:common ................... SUCCESS [5.899s] 
online-table-reservation:zuul-server .............. SUCCESS [4.517s] 
online-table-reservation:restaurant-service ....... SUCCESS [49.250s] 
online-table-reservation:eureka-server ............ SUCCESS [2.850s] online-table-reservation:dashboard-server ......... SUCCESS [2.893s] 
online-table-reservation:turbine-server ........... SUCCESS [3.670s] 
online-table-reservation:user-service ............. SUCCESS [47.983s] 
online-table-reservation:api-service .............. SUCCESS [3.065s] 
online-table-reservation:booking-service .......... SUCCESS [26.496s] 
```

然后，命令提示符上进入`<path to source>/6392_chapter5`并运行以下命令：

```java
java -jar eureka-server/target/eureka-server.jar 
java -jar turbine-server/target/turbine-server.jar 
java -jar dashboard-server/target/dashboard-server.jar 
java -jar restaurant-service/target/restaurant-service.jar 
java -jar user-service/target/user-service.jar 
java -jar booking-service/target/booking-service.jar 
java -jar api-service/target/api-service.jar 
```

注意：在启动 Zuul 服务之前，请确保 Eureka 仪表板上的所有服务都处于启动状态：`http://localhost:8761/`：

```java
java -jar zuul-server/target/zuul-server.jar 
```

再次检查 Eureka 仪表板，所有应用程序都应该处于启动状态。然后进行测试。

# 使用容器部署微服务

读完第一章《解决方案方法》后，您可能已经理解了 Docker 的要点。

Docker 容器提供了一个轻量级的运行时环境，由虚拟机的核心功能和操作系统的隔离服务组成，称为 Docker 镜像。Docker 使微服务的打包和执行变得更加简单。每个操作系统可以有多个 Docker，每个 Docker 可以运行单个应用程序。

# 安装与配置

如果您不使用 Linux 操作系统，Docker 需要一个虚拟化服务器。您可以安装 VirtualBox 或类似的工具，如 Docker Toolbox，使其适用于您。Docker 安装页面提供了更多关于它的细节，并告诉您如何执行。所以，请参考 Docker 网站上的 Docker 安装指南。

你可以根据你的平台，通过遵循给出的说明安装 Docker：[`docs.docker.com/engine/installation/`](https://docs.docker.com/engine/installation/)。

DockerToolbox-1.9.1f 是在写作时可用的最新版本。这个版本我们使用了。

# 具有 4GB 内存的 Docker 虚拟机

默认的虚拟机创建时会分配 2GB 的内存。我们将重新创建一个具有 4GB 内存的 Docker 虚拟机：

```java
 docker-machine rm default
 docker-machine create -d virtualbox --virtualbox-memory 4096 default

```

# 使用 Maven 构建 Docker 镜像

有多种 Docker Maven 插件可以使用：

+   [`github.com/rhuss/docker-maven-plugin`](https://github.com/rhuss/docker-maven-plugin)

+   [`github.com/alexec/docker-maven-plugin`](https://github.com/alexec/docker-maven-plugin)

+   [`github.com/spotify/docker-maven-plugin`](https://github.com/spotify/docker-maven-plugin)

你可以根据你的选择使用这些方法中的任何一个。我发现由`@rhuss`编写的 Docker Maven 插件最适合我们使用。这个插件定期更新，并且相比其他插件拥有许多额外的功能。

在讨论`docker-maven-plugin`的配置之前，我们需要在`application.yml`中引入 Docker Spring 配置文件。这样我们在为不同平台构建服务时，工作会更加容易。我们需要配置以下四个属性：

+   我们将使用标识为 Docker 的 Spring 配置文件。

+   由于服务将在它们自己的容器中执行，所以嵌入式 Tomcat 之间不会有端口冲突。现在我们可以使用端口`8080`。

+   我们更倾向于使用 IP 地址来在我们的 Eureka 中注册服务。因此，Eureka 实例属性`preferIpAddress`将被设置为`true`。

+   最后，我们将在`serviceUrl:defaultZone`中使用 Eureka 服务器的主机名。

要在你的项目中添加 Spring 配置文件，请在`application.yml`中现有内容之后添加以下行：

```java
--- 
# For deployment in Docker containers 
spring: 
  profiles: docker 

server: 
  port: 8080 

eureka: 
  instance: 
    preferIpAddress: true 
  client: 
    serviceUrl: 
      defaultZone: http://eureka:8761/eureka/ 
```

使用命令`mvn -P docker clean package`将生成带有 Tomcat 的`8080`端口的`service` JAR，并且该 JAR 会在 Eureka 服务器上以主机名`eureka`注册。

现在，让我们配置`docker-maven-plugin`以构建带有我们的餐厅微服务的镜像。这个插件首先必须创建一个 Dockerfile。Dockerfile 在两个地方配置——在`pom.xml`和`docker-assembly.xml`文件中。我们将在`pom.xml`文件中使用以下的插件配置：

```java
<properties> 
<!-- For Docker hub leave empty; use "localhost:5000/" for a local Docker Registry --> 
  <docker.registry.name>localhost:5000/</docker.registry.name> 
  <docker.repository.name>${docker.registry.name}sourabhh /${project.artifactId}</docker.repository.name> 
</properties> 
... 
<plugin> 
  <groupId>org.jolokia</groupId> 
  <artifactId>docker-maven-plugin</artifactId> 
  <version>0.13.7</version> 
  <configuration> 
    <images> 
      <image> 
<name>${docker.repository.name}:${project.version}</name> 
        <alias>${project.artifactId}</alias> 

        <build> 
          <from>java:8-jre</from> 
          <maintainer>sourabhh</maintainer> 
          <assembly> 
            <descriptor>docker-assembly.xml</descriptor> 
          </assembly> 
          <ports> 
            <port>8080</port> 
          </ports> 
          <cmd> 
            <shell>java -jar \ 
              /maven/${project.build.finalName}.jar server \ 
              /maven/docker-config.yml</shell> 
          </cmd> 
        </build> 
        <run> 
        <!-- To Do --> 
        </run> 
      </image> 
    </images> 
  </configuration> 
</plugin> 
```

在 Docker Maven 插件配置之前创建一个 Dockerfile，该 Dockerfile 扩展了 JRE 8（`java:8-jre`）的基础镜像。这个镜像暴露了端口`8080`和`8081`。

接下来，我们将配置`docker-assembly.xml`文件，该文件告诉插件哪些文件应该被放入容器中。这个文件将被放置在`src/main/docker`目录下：

```java
<assembly   
  xsi:schemaLocation="http://maven.apache.org/plugins/maven-assembly-plugin/assembly/1.1.2 http://maven.apache.org/xsd/assembly-1.1.2.xsd"> 
  <id>${project.artifactId}</id> 
  <files> 
    <file> 
      <source>{basedir}/target/${project.build.finalName}.jar</source> 
      <outputDirectory>/</outputDirectory> 
    </file> 
    <file> 
      <source>src/main/resources/docker-config.yml</source> 
      <outputDirectory>/</outputDirectory> 
    </file> 
  </files> 
</assembly> 
```

前面的组装，在生成的 Dockerfile 中添加了`service` JAR 和`docker-config.yml`文件。这个 Dockerfile 位于`target/docker/`目录下。打开这个文件，你会发现内容与这个类似：

```java
FROM java:8-jre 
MAINTAINER sourabhh 
EXPOSE 8080 
COPY maven /maven/ 
CMD java -jar \ 
  /maven/restaurant-service.jar server \ 
  /maven/docker-config.yml 
```

之前的文件可以在 `restaurant-service\target\docker\sousharm\restaurant-service\PACKT-SNAPSHOT\build` 目录中找到。`build` 目录还包含 `maven` 目录，其中包含 `docker-assembly.xml` 文件中提到的所有内容。

让我们来构建 Docker 镜像：

```java
mvn docker:build

```

一旦此命令完成，我们可以使用 Docker 镜像在本地仓库中验证镜像，或者通过运行以下命令来实现：

```java
docker run -it -p 8080:8080 sourabhh/restaurant-service:PACKT-SNAPSHOT

```

使用 `-it` 来在前台执行此命令，而不是 `-d`。

# 使用 Maven 运行 Docker

要用 Maven 执行 Docker 镜像，我们需要在 `pom.xml` 文件中添加以下配置。`<run>` 块，放在 `pom.xml` 文件中 `docker-maven-plugin` 部分下的 `docker-maven-plugin` 块中标记的 `To Do` 下面：

```java
<properties> 
  <docker.host.address>localhost</docker.host.address> 
  <docker.port>8080</docker.port> 
</properties> 
... 
<run> 
  <namingStrategy>alias</namingStrategy> 
  <ports> 
    <port>${docker.port}:8080</port> 
  </ports> 
  <wait> 
    <url>http://${docker.host.address}:${docker.port}/v1/restaurants/1</url> 
    <time>100000</time> 
  </wait> 
  <log> 
    <prefix>${project.artifactId}</prefix> 
    <color>cyan</color> 
  </log> 
</run> 
```

这里，我们已经定义了运行我们的 Restaurant 服务容器的参数。我们将 Docker 容器端口 `8080` 和 `8081` 映射到宿主系统的端口，这使我们能够访问服务。同样，我们也将容器的 `log` 目录绑定到宿主系统的 `<home>/logs` 目录。

Docker Maven 插件可以通过轮询管理后端的 ping URL 来检测容器是否已完成启动。

请注意，如果您在 Windows 或 MacOS X 上使用 DockerToolbox 或 boot2docker，Docker 主机不是 localhost。您可以执行 `docker-machine ip default` 来检查 Docker 镜像 IP。在启动时也会显示。

Docker 容器准备启动。使用以下命令使用 Maven 启动它：

```java
mvn docker:start
```

# 使用 Docker 进行集成测试

启动和停止 Docker 容器可以通过在 `pom.xml` 文件中的 `docker-maven-plugin` 生命周期阶段绑定以下执行来实现：

```java
<execution> 
  <id>start</id> 
  <phase>pre-integration-test</phase> 
  <goals> 
    <goal>build</goal> 
    <goal>start</goal> 
  </goals> 
</execution> 
<execution> 
  <id>stop</id> 
  <phase>post-integration-test</phase> 
  <goals> 
    <goal>stop</goal> 
  </goals> 
</execution> 
```

现在我们将配置 Failsafe 插件，使用 Docker 执行集成测试。这允许我们执行集成测试。我们在 `service.url` 标签中传递了服务 URL，这样我们的集成测试就可以使用它来执行集成测试。

我们将使用 `DockerIntegrationTest` 标记来标记我们的 Docker 集成测试。它定义如下：

```java
package com.packtpub.mmj.restaurant.resources.docker; 

public interface DockerIT { 
    // Marker for Docker integration Tests 
} 
```

看看下面的集成 `plugin` 代码。你可以看到 `DockerIT` 被配置为包含集成测试（Failsafe 插件），而它被用于在单元测试中排除（Surefire 插件）：

```java
<plugin> 
                <groupId>org.apache.maven.plugins</groupId> 
                <artifactId>maven-failsafe-plugin</artifactId> 
                <configuration> 
                    <phase>integration-test</phase> 
                    <groups>com.packtpub.mmj.restaurant.resources.docker.DockerIT</groups> 
                    <systemPropertyVariables> 
                        <service.url>http://${docker.host.address}:${docker.port}/</service.url> 
                    </systemPropertyVariables> 
                </configuration> 
                <executions> 
                    <execution> 
                        <goals> 
                            <goal>integration-test</goal> 
                            <goal>verify</goal> 
                        </goals> 
                    </execution> 
                </executions> 
       </plugin> 
       <plugin> 
                <groupId>org.apache.maven.plugins</groupId> 
                <artifactId>maven-surefire-plugin</artifactId> 
                <configuration>             <excludedGroups>com.packtpub.mmj.restaurant.resources.docker.DockerIT</excludedGroups> 
                </configuration> 
</plugin> 

```

一个简单的集成测试看起来像这样：

```java
@Category(DockerIT.class) 
public class RestaurantAppDockerIT { 

    @Test 
    public void testConnection() throws IOException { 
        String baseUrl = System.getProperty("service.url"); 
        URL serviceUrl = new URL(baseUrl + "v1/restaurants/1"); 
        HttpURLConnection connection = (HttpURLConnection) serviceUrl.openConnection(); 
        int responseCode = connection.getResponseCode(); 
        assertEquals(200, responseCode); 
    } 
} 
```

您可以使用以下命令执行使用 Maven 的集成测试（请确保在运行集成测试之前从项目目录的根目录运行 `mvn clean install`）：

```java
mvn integration-test

```

# 将镜像推送到注册表

在 `docker-maven-plugin` 下添加以下标签以将 Docker 镜像发布到 Docker hub：

```java
<execution> 
  <id>push-to-docker-registry</id> 
  <phase>deploy</phase> 
  <goals> 
    <goal>push</goal> 
  </goals> 
</execution> 
```

您可以通过使用以下配置跳过 JAR 发布，为 `maven-deploy-plugin`：

```java
<plugin> 
  <groupId>org.apache.maven.plugins</groupId> 
  <artifactId>maven-deploy-plugin</artifactId> 
  <version>2.7</version> 
  <configuration> 
    <skip>true</skip> 
  </configuration> 
</plugin> 
```

在 Docker hub 发布 Docker 镜像也需要用户名和密码：

```java
mvn -Ddocker.username=<username> -Ddocker.password=<password> deploy
```

您还可以将 Docker 镜像推送到您自己的 Docker 注册表。为此，请添加

如下代码所示，添加`docker.registry.name`标签。例如，

如果你的 Docker 注册表可在`xyz.domain.com`端口`4994`上访问，那么定义

通过添加以下代码行：

```java
<docker.registry.name>xyz.domain.com:4994</docker.registry.name> 
```

这不仅完成了部署，还可以测试我们的 Docker 化服务。

# 管理 Docker 容器

每个微服务都将有自己的 Docker 容器。因此，我们将使用`Docker Compose`来管理我们的容器。

Docker Compose 将帮助我们指定容器的数量以及这些容器的执行方式。我们可以指定 Docker 镜像、端口以及每个容器与其他 Docker 容器的链接。

我们将在根项目目录中创建一个名为`docker-compose.yml`的文件，并将所有微服务容器添加到其中。我们首先指定 Eureka 服务器，如下所示：

```java
eureka: 
  image: localhost:5000/sourabhh/eureka-server 
  ports: 
    - "8761:8761" 
```

在这里，`image`代表 Eureka 服务器的发布 Docker 镜像，`ports`代表执行 Docker 镜像的主机和 Docker 主机的映射。

这将启动 Eureka 服务器，并为外部访问发布指定的端口。

现在我们的服务可以使用这些容器（如 Eureka 的依赖容器）。让我们看看`restaurant-service`如何可以链接到依赖容器。很简单；只需使用`links`指令：

```java
restaurant-service: 
  image: localhost:5000/sourabhh/restaurant-service 
  ports: 
    - "8080:8080" 
  links: 
    - eureka 
```

上述链接声明将更新`restaurant-service`容器中的`/etc/hosts`文件，每个服务占一行，`restaurant-service`依赖的服务（假设`security`容器也链接了），例如：

```java
192.168.0.22  security 
192.168.0.31  eureka 
```

如果你没有设置本地 Docker 注册表，那么为了无问题或更平滑的执行，请先设置。

通过运行以下命令构建本地 Docker 注册表：

**docker run -d -p 5000:5000 --restart=always --name registry registry:2**

然后，为本地镜像执行推送和拉取命令：

**docker push localhost:5000/sourabhh/restaurant-service:PACKT-SNAPSHOT**

**docker-compose pull**

最后，执行 docker-compose:

**docker-compose up -d**

一旦所有微服务容器（服务和服务器）都配置好了，我们可以用一个命令启动所有 Docker 容器：

```java
docker-compose up -d
```

这将启动 Docker Compose 中配置的所有 Docker 容器。以下命令将列出它们：

```java
docker-compose ps
Name                                          Command
                State           Ports
-------------------------------------------------------------
onlinetablereservation5_eureka_1         /bin/sh -c java -jar         ...               Up      0.0.0.0:8761->8761/tcp

onlinetablereservation5_restaurant-service_1  /bin/sh -c java -jar       ...   Up      0.0.0.0:8080->8080/tcp

```

您还可以使用以下命令检查 Docker 镜像日志：

```java
docker-compose logs
[36mrestaurant-service_1 | ←[0m2015-12-23 08:20:46.819  INFO 7 --- [pool-3-thread-1] com.netflix.discovery.DiscoveryClient    : DiscoveryClient_RESTAURANT-SERVICE/172.17
0.4:restaurant-service:93d93a7bd1768dcb3d86c858e520d3ce - Re-registering apps/RESTAURANT-SERVICE
[36mrestaurant-service_1 | ←[0m2015-12-23 08:20:46.820  INFO 7 --- [pool-3-thread-1] com.netflix.discovery.DiscoveryClient    : DiscoveryClient_RESTAURANT-SERVICE/172.17
0.4:restaurant-service:93d93a7bd1768dcb3d86c858e520d3ce: registering service... [36mrestaurant-service_1 | ←[0m2015-12-23 08:20:46.917  INFO 7 --- [pool-3-thread-1] com.netflix.discovery.DiscoveryClient    : DiscoveryClient_RESTAURANT-SERVICE/172.17

```

# 参考文献

以下链接将为您提供更多信息：

+   **Netflix** **Ribbon**: [`github.com/Netflix/ribbon`](https://github.com/Netflix/ribbon)

+   **Netflix** **Zuul**: [`github.com/Netflix/zuul`](https://github.com/Netflix/zuul)

+   **RabbitMQ**: [`www.rabbitmq.com/download.html`](https://www.rabbitmq.com/download.html)

+   **Hystrix**: [`github.com/Netflix/Hystrix`](https://github.com/Netflix/Hystrix)

+   **Turbine**: [`github.com/Netflix/Turbine`](https://github.com/Netflix/Turbine)

+   **Docker**: [`www.docker.com/`](https://www.docker.com/)

# 摘要

在本章中，我们学习了关于微服务管理的一系列特性：负载均衡、边缘（网关）服务器、断路器以及监控。在本章学习结束后，你应该知道如何实现负载均衡和路由。我们也学习了如何设置和配置边缘服务器。本章还介绍了另一个重要的安全机制。通过使用 Docker 或其他容器，可以使部署变得简单。本章通过 Maven 构建演示并集成了 Docker。

从测试的角度来看，我们对服务的 Docker 镜像进行了集成测试。我们还探讨了编写客户端的方法，例如`RestTemplate`和 Netflix Feign。

在下一章中，我们将学习如何通过身份验证和授权来保护微服务。我们还将探讨微服务安全的其他方面。


# 第六章：响应式微服务

在本章中，我们将使用 Spring Boot、Spring Stream、Apache Kafka 和 Apache Avro 来实现响应式微服务。我们将利用现有的 Booking 微服务来实现消息生产者，或者说，生成事件。我们还将创建一个新的微服务（Billing），用于消费由更新的 Booking 微服务产生的消息，或者说，用于消费由 Booking 微服务生成的事件。我们还将讨论 REST-based 微服务和事件-based 微服务之间的权衡。

在本章中，我们将涵盖以下主题：

+   响应式微服务架构概述

+   生成事件

+   消费事件

# 响应式微服务架构概述

到目前为止，我们所开发的微服务是基于 REST 的。我们使用 REST 进行内部（微服务之间的通信，其中一个微服务与同一系统中的另一个微服务进行通信）和外部（通过公共 API）通信。目前，REST 最适合公共 API。对于微服务之间的通信，还有其他选择吗？实现 REST 用于微服务之间通信的最佳方法是什么？我们将在本节中讨论所有这些问题。

你可以构建完全是异步的微服务。你可以构建基于微服务的系统，这种系统将基于事件进行通信。REST 和基于事件 的微服务之间有一个权衡。REST 提供同步通信，而响应式微服务则基于异步通信（异步消息传递）。

我们可以为微服务之间的通信使用异步通信。根据需求和功能，我们可以选择 REST 或异步消息传递。考虑一个用户下订单的示例案例，这对于实现响应式微服务来说是一个非常好的案例。在成功下单后，库存服务将重新计算可用商品；账户服务将维护交易；通信服务将向所有涉及的用户（如客户和供应商）发送消息（短信、电子邮件等）。在这种情况下，一个微服务可能会根据另一个微服务执行的操作（下单）执行不同的操作（库存、账户、消息传递等）。现在，想想如果所有的这些通信都是同步的。相反，通过异步消息传递实现的响应式通信，提供了硬件资源的高效利用、非阻塞、低延迟和高吞吐量操作。

我们可以将微服务实现主要分为两组——REST-based 微服务和事件-based/消息驱动的微服务。响应式微服务是基于事件的。

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/42dd3919-b165-4b8a-b0d2-ec2cf4aacd8b.png)

响应式宣言

- 响应式微服务基于响应式宣言（[`www.reactivemanifesto.org/`](https://www.reactivemanifesto.org/)）。响应式宣言包括四个原则，我们现在将讨论这些原则。

# - 响应性

- 响应性是及时服务请求的特征。它由延迟来衡量。生产者应及时提供响应，消费者应及时接收响应。对于请求执行的操作链中的故障，不应导致响应延迟或失败。因此，这对于服务的可用性非常重要。

# - 弹性

- 一个有弹性的系统也是一个健壮的系统。弹性原则与响应性原则相一致。微服务在遇到故障时，仍应提供响应，如果微服务的某个实例宕机，请求应由同一微服务的另一个节点处理。一个有弹性的微服务系统能够处理各种故障。所有服务都应受到监控，以检测故障，并且所有故障都应得到处理。我们在上一章使用了服务发现 Eureka 进行监控和 Hystrix 实现断路器模式。

# - 弹性

- 一个反应式的系统如果通过利用硬件和其他资源来对负载做出反应，那么它是弹性的。如果需求增加，它可以实例化微服务或微服务的新实例，反之亦然。在特别的销售日，如黑色星期五、圣诞节、排灯节等，反应式的购物应用会实例化更多的微服务节点，以分担增加请求的负载。在正常日子，购物应用可能不需要比平均更多的资源，因此它可以减少节点的数量。因此，为了有效地使用硬件，反应式系统应该是弹性的。

# - 消息驱动

- 如果反应式系统没有事情可做，它就会闲置；如果它本无任务，它就不会无用地使用资源。一个事件或消息可以使反应式微服务变得活跃，并开始处理（反应）接收到的该事件/消息（请求）。理想情况下，通信应该是异步和非阻塞的。反应式系统通过消息进行通信——异步消息传递。在本章中，我们将使用 Apache Kafka 进行消息传递。

理想情况下，反应式编程语言是实现反应式微服务的最佳方式。反应式编程语言提供异步和非阻塞调用。Java 也可以利用 Java 流功能来开发反应式微服务。Kafka 将使用 Kafka 的 Java 库和插件进行消息传递。我们已经实现了服务发现和注册服务（Eureka Server-监控），利用 Eureka 实现弹性代理服务器（Zuul），以及利用 Eureka 和 Hystrix 实现断路器（弹性响应）。在下一节中，我们将实现基于消息的微服务。

# 实现反应式微服务

反应式微服务响应事件执行操作。我们将修改我们的代码以产生和消费我们示例实现的事件。虽然我们将创建一个单一事件，但微服务可以有多个生产者或消费者事件。此外，微服务可以同时具有生产者和消费者事件。我们将利用 Booking 微服务中现有的功能来创建新预订（`POST /v1/booking`）。这将作为我们的事件源，并使用 Apache Kafka 发送此事件。其他微服务可以通过监听此事件来消费该事件。在成功预订调用后，Booking 微服务将产生 Kafka 主题（事件）`amp.bookingOrdered`。我们将创建一个与创建其他微服务（如 Booking）相同方式的新微服务 Billing，用于消费此事件（`amp.bookingOrdered`）。

# 产生事件

一旦产生事件，对象就会被发送到 Kafka。同样，Kafka 会将这个产生的对象发送给所有监听器（微服务）。简而言之，产生的对象通过网络传输。因此，我们需要为这些对象提供序列化支持。我们将使用 Apache Avro 进行数据序列化。它定义了以 JSON 格式表示的数据结构（架构），并为 Maven 和 Gradle 提供了一个插件，使用 JSON 架构生成 Java 类。Avro 与 Kafka 配合很好，因为 Avro 和 Kafka 都是 Apache 产品，彼此之间集成非常紧密。

让我们先定义一个代表创建新预订时通过网络发送的对象的架构。正如之前提到的用于产生事件的 Booking 微服务，我们将在 Booking 微服务的`src/main/resources/avro`目录中创建 Avro 架构文件`bookingOrder.avro`。

`bookingOrder.avro`文件看起来像这样：

```java
{"namespace": "com.packtpub.mmj.booking.domain.valueobject.avro", 
 "type": "record", 
 "name": "BookingOrder", 
 "fields": [ 
     {"name": "id", "type": "string"}, 
     {"name": "name", "type": "string", "default": ""}, 
     {"name": "userId", "type": "string", "default": ""}, 
     {"name": "restaurantId", "type": "string", "default": ""}, 
     {"name": "tableId", "type": "string", "default": ""}, 
     {"name": "date", "type": ["null", "string"], "default": null}, 
     {"name": "time", "type": ["null", "string"], "default": null} 
 ] 
}  
```

在这里，`namespace`代表包`type`，`record`代表类，`name`代表类名，而`fields`代表类的属性。当我们使用此架构生成 Java 类时，它将在`com.packtpub.mmj.booking.domain.valueobject.avro`包中创建新的 Java 类`BookingOrder.java`，`fields`中定义的所有属性都将包含在这个类中。

在`fields`中，也有`name`和`type`，它们表示属性的名称和类型。对于所有字段，我们都使用了输入`type`作为`string`。您还可以使用其他基本类型，如`boolean`、`int`和`double`。此外，您可以使用复杂类型，如`record`（在上面的代码片段中使用）、`enum`、`array`和`map`。`default`类型表示属性的默认值。

前面的模式将用于生成 Java 代码。我们将使用`avro-maven-plugin`从前面的 Avro 模式生成 Java 源文件。我们将在此插件的子`pom`文件（服务的`pom.xml`）的插件部分添加此插件：

```java
<plugin> 
    <groupId>org.apache.avro</groupId> 
    <artifactId>avro-maven-plugin</artifactId> 
    <version>1.8.2</version> 
    <executions> 
        <execution> 
            <phase>generate-sources</phase> 
            <goals> 
                <goal>schema</goal> 
            </goals> 
            <configuration> 
               <sourceDirectory>${project.basedir}/src/main/resources/avro/</sourceDirectory> 
               <outputDirectory>${project.basedir}/src/main/java/</outputDirectory> 
            </configuration> 
        </execution> 
    </executions> 
</plugin> 
```

您可以看到，在`configuration`部分，已经配置了`sourceDirectory`和`outputDirectory`。因此，当我们运行`mvn package`时，它将在配置的`outputDirectory`内部的`com.packtpub.mmj.booking.domain.valueobject.avro`包中创建`BookingOrder.java`文件。

现在既然我们的 Avro 模式和生成的 Java 源代码已经可用，我们将添加生成事件所需的 Maven 依赖项。

在 Booking 微服务`pom.xml`文件中添加依赖项：

```java
... 
<dependency> 
    <groupId>org.apache.avro</groupId> 
    <artifactId>avro</artifactId> 
    <version>1.8.2</version> 
</dependency> 
<dependency> 
    <groupId>org.springframework.cloud</groupId> 
    <artifactId>spring-cloud-stream</artifactId> 
    <version>2.0.0.M1</version> 
</dependency> 
<dependency> 
    <groupId>org.springframework.cloud</groupId> 
    <artifactId>spring-cloud-starter-stream-kafka</artifactId> 
</dependency> 
<dependency> 
    <groupId>org.apache.kafka</groupId> 
    <artifactId>kafka-clients</artifactId> 
    <version>0.11.0.1</version> 
</dependency> 
<dependency> 
    <groupId>org.springframework.cloud</groupId> 
    <artifactId>spring-cloud-stream-schema</artifactId> 
</dependency> 
... 
```

在这里，我们添加了三个主要依赖项：`avro`、`spring-cloud-stream`和`kafka-clients`。此外，我们还添加了与 Kafka 的流集成（`spring-cloud-starter-stream-kafka`）和流支持模式（`spring-cloud-stream-schema`）。

现在，既然我们的依赖项已经就位，我们可以开始编写生产者实现。Booking 微服务将发送`amp.bookingOrdered`事件到 Kafka 流。我们将声明为此目的的消息通道。可以通过使用`Source.OUTPUT`与`@InboundChannelAdapter`注解，或者通过声明 Java 接口来完成。我们将使用接口方法，因为这更容易理解且有关联。

我们将在`com.packtpub.mmj.booking.domain.service.message`包中创建`BookingMessageChannels.java`消息通道。在这里，我们可以添加所有必需的消息通道。由于我们使用单事件样本实现，我们只需声明`bookingOrderOutput`。

`BookingMessageChannels.java`文件将看起来像这样：

```java
package com.packtpub.mmj.booking.domain.message; 

import org.springframework.cloud.stream.annotation.Output; 
import org.springframework.messaging.MessageChannel; 

public interface BookingMessageChannels { 

    public final static String BOOKING_ORDER_OUTPUT = "bookingOrderOutput"; 

    @Output(BOOKING_ORDER_OUTPUT) 
    MessageChannel bookingOrderOutput(); 
} 
```

在这里，我们只是使用`@Output`注解定义了消息通道的名称，`bookingOrderOutput`。我们还需要在`application.yaml`中配置此消息通道。我们将在`application.yaml`文件中使用此名称定义 Kafka 主题：

```java
spring: 
  cloud: 
    stream: 
        bindings: 
            bookingOrderOutput: 
                destination: amp.bookingOrdered 
```

在这里，给出了 Kafka 主题名称`amp.bookingOrdered`，它与`bookingOrderOutput`消息通道绑定。（Kafka 主题名称可以是任何字符串。我们添加`amp`前缀以表示异步消息传递；您可以使用带或不带前缀的 Kafka 主题名称。）

我们还需要一个消息转换器，用于将`BookingOrder`对象发送到 Kafka。为此，我们将在 Booking 服务的主类中创建一个`@Bean`注解，以返回 Spring 的`MessageConverter`。

`BookingApp.class`文件中的`@Bean`注解看起来像这样：

```java
... 
@Bean 
public MessageConverter bookingOrderMessageConverter() throws IOException { 
    LOG.info("avro message converter bean initialized."); 
    AvroSchemaMessageConverter avroSchemaMessageConverter = new AvroSchemaMessageConverter(MimeType.valueOf("application/bookingOrder.v1+avro")); 
    avroSchemaMessageConverter.setSchemaLocation(new ClassPathResource("avro/bookingOrder.avsc")); 
    return avroSchemaMessageConverter; 
} 
... 
```

您可以根据所需的模式添加更多的豆子。我们还没有在`application.yaml`中配置 Kafka 服务器，默认为`localhost`。让我们来做这件事。

在`application.yaml`文件中配置 Kafka 服务器：

```java
spring: 
  cloud: 
    stream: 
        kafka: 
            binder: 
                zkNodes: localhost 
            binder: 
                brokers: localhost 
```

在这里，我们为`zkNodes`和`brokers`都配置了`localhost`；您可以将其更改为托管 Kafka 的主机。

我们已经准备好将`amp.bookingOrdered` Kafka 主题发送到 Kafka 服务器。为了简单起见，我们将在`BookingServiceImpl.java`类中直接添加一个`produceBookingOrderEvent`方法，该方法接受`Booking`类作为参数（您需要在`BookingService.java`中添加相同的签名方法）。让我们先看看代码。

`BookingServiceImpl.java`文件如下：

```java
... 
@EnableBinding(BookingMessageChannels.class) 
public class BookingServiceImpl extends BaseService<Booking, String> 
        implements BookingService { 
... 
... 
private BookingMessageChannels bookingMessageChannels; 

@Autowired 
public void setBookingMessageChannels(BookingMessageChannels bookingMessageChannels) { 
    this.bookingMessageChannels = bookingMessageChannels; 
} 

@Override 
public void add(Booking booking) throws Exception { 
    ... 
    ... 
    super.add(booking); 
    produceBookingOrderEvent(booking); 
} 
... 
...     
@Override 
public void produceBookingOrderEvent(Booking booking) throws Exception { 
    final BookingOrder.Builder boBuilder = BookingOrder.newBuilder(); 
    boBuilder.setId(booking.getId()); 
    boBuilder.setName(booking.getName()); 
    boBuilder.setRestaurantId(booking.getRestaurantId()); 
    boBuilder.setTableId(booking.getTableId()); 
    boBuilder.setUserId(booking.getUserId()); 
    boBuilder.setDate(booking.getDate().toString()); 
    boBuilder.setTime(booking.getTime().toString()); 
    BookingOrder bo = boBuilder.build(); 
    final Message<BookingOrder> message = MessageBuilder.withPayload(bo).build(); 
    bookingMessageChannels.bookingOrderOutput().send(message); 
    LOG.info("sending bookingOrder: {}", booking); 
} 
... 
```

在这里，我们声明了`bookingMessageChannel`对象，该对象通过`setter`方法进行自动注入。Spring Cloud Stream 注解`@EnableBinding`将`bookingOrderOutput`消息通道绑定在`BookingMessageChannels`类中声明的`bookingOrderOutput`消息通道。

添加了`produceBookingOrderEvent`方法，该方法接受`booking`对象。在`produceBookingOrderEvent`方法内部，使用`booking`对象设置`BookingOrder`对象属性。然后使用`bookingOrder`对象构建消息。最后，通过`bookingMessageChannels`将消息发送到 Kafka。

`produceBookingOrderEvent`方法在预约成功保存在数据库后调用。

为了测试这个功能，您可以使用以下命令运行 Booking 微服务：

```java
java -jar booking-service/target/booking-service.jar
```

确保 Kafka 和 Zookeeper 应用程序在`application.yaml`文件中定义的主机和端口上正确运行，以进行成功的测试。

然后，通过任何 REST 客户端向`http://<host>:<port>/v1/booking`发送一个预约的 POST 请求，并带有以下载荷：

```java
{ 
                "id": "999999999999",  
                "name": "Test Booking 888",  
                "userId": "3",  
                "restaurantId": "1",  
                "tableId": "1",  
                "date": "2017-10-02",  
                "time": "20:20:20.963543300" 
} 

```

它将产生`amp.bookingOrdered` Kafka 主题（事件），如下所示，在 Booking 微服务控制台上发布日志：

```java
2017-10-02 20:22:17.538  INFO 4940 --- [nio-7052-exec-1] c.p.m.b.d.service.BookingServiceImpl     : sending bookingOrder: {id: 999999999999, name: Test Booking 888, userId: 3, restaurantId: 1, tableId: 1, date: 2017-10-02, time: 20:20:20.963543300} 
```

同样，Kafka 控制台将显示以下消息，确认消息已成功由 Kafka 接收：

```java
[2017-10-02 20:22:17,646] INFO Updated PartitionLeaderEpoch. New: {epoch:0, offset:0}, Current: {epoch:-1, offset-1} for Partition: amp.bookingOrdered-0\. Cache now contains 0 entries. (kafka.server.epoch.LeaderEpochFileCache) 

```

现在，我们可以移动到编写之前生成的事件的消费者代码。

# 消费事件

首先，我们将在父级`pom.xml`文件中添加新模块`billing-service`，并以与其他微服务相同的方式创建 Billing 微服务第五章，*部署和测试*。我们为 Booking 微服务编写的几乎所有反应式代码都将被 Billing 微服务重用，例如 Avro 模式和`pom.xml`条目。

我们将在账单微服务中以与预订微服务相同的方式添加 Avro 模式。由于账单微服务的模式命名空间（包名）将是相同的`booking`包，我们需要在`@SpringBootApplication`注解的`scanBasePackages`属性中添加值`com.packtpub.mmj.booking`。这将允许 spring 上下文也扫描预订包。

我们将在账单微服务的`pom.xml`中添加以下依赖项，这与我们在预订微服务中添加的依赖项相同。

账单微服务的`pom.xml`文件如下：

```java
... 
... 
<dependency> 
    <groupId>org.apache.avro</groupId> 
    <artifactId>avro</artifactId> 
    <version>1.8.2</version> 
</dependency> 
<dependency> 
    <groupId>org.springframework.cloud</groupId> 
    <artifactId>spring-cloud-stream</artifactId> 
    <version>2.0.0.M1</version> 
</dependency> 
<dependency> 
    <groupId>org.springframework.cloud</groupId> 
    <artifactId>spring-cloud-starter-stream-kafka</artifactId> 
</dependency> 
<dependency> 
    <groupId>org.apache.kafka</groupId> 
    <artifactId>kafka-clients</artifactId> 
    <version>0.11.0.1</version> 
</dependency> 
<dependency> 
    <groupId>org.springframework.cloud</groupId> 
    <artifactId>spring-cloud-stream-schema</artifactId> 
</dependency> 
... 
... 
```

您可以参考预订服务依赖段落，了解添加这些依赖的原因。

接下来，我们将向账单微服务中添加消息通道，如下所示：

```java
package com.packtpub.mmj.billing.domain.message; 

import org.springframework.cloud.stream.annotation.Input; 
import org.springframework.messaging.MessageChannel; 

public interface BillingMessageChannels { 

    public final static String BOOKING_ORDER_INPUT = "bookingOrderInput"; 

    @Input(BOOKING_ORDER_INPUT) 
    MessageChannel bookingOrderInput(); 
} 
```

这里，我们正在为预订服务中的输出消息通道添加一个输入消息通道的对端。请注意`bookingOrderInput`是一个带有`@input`注解的输入消息通道。

接下来，我们想要将`bookingOrderInput`通道配置为 Kafka 主题`amp.BookingOrdered`。为此，我们将修改`application.yaml`：

```java
 spring: 
  ... 
  ... 
  cloud: 
    stream: 
        bindings: 
            bookingOrderInput: 
                destination: amp.bookingOrdered 
                consumer: 
                    resetOffsets: true 
                group: 
                    ${bookingConsumerGroup} 
bookingConsumerGroup: "booking-service" 
```

这里，通过目标属性将 Kafka 主题添加到`bookingOrderInput`通道。我们还将按照在预订微服务中配置的方式在账单微服务（`application.yaml`）中配置 Kafka：

```java
        kafka: 
            binder:                
                zkNodes: localhost 
            binder: 
                brokers: localhost 
```

现在，我们将添加一个事件监听器，该监听器将监听与`bookingOrderInput`消息通道绑定的流，使用 Spring Cloud Steam 库中可用的`@StreamListener`注解。

`EventListener.java`文件如下：

```java
package com.packtpub.mmj.billing.domain.message; 

import com.packtpub.mmj.billing.domain.service.TweetMapper; 
import com.packtpub.mmj.billing.domain.service.TweetReceiver; 
import com.packtpub.mmj.billing.domain.service.WebSocketTweetReceiver; 
import com.packtpub.mmj.billing.domain.valueobject.TweetInput; 
import com.packtpub.mmj.booking.domain.valueobject.avro.BookingOrder; 
import com.packtpub.mmj.booking.domain.valueobject.avro.TweetDto; 
import org.slf4j.Logger; 
import org.slf4j.LoggerFactory; 
import org.springframework.beans.factory.annotation.Autowired; 
import org.springframework.cloud.stream.annotation.StreamListener; 

public class EventListener { 

    private static final Logger LOG = LoggerFactory.getLogger(WebSocketTweetReceiver.class); 

    @StreamListener(BillingMessageChannels.BOOKING_ORDER_INPUT) 
    public void consumeBookingOrder(BookingOrder bookingOrder) { 
        LOG.info("Received BookingOrder: {}", bookingOrder); 
    } 
} 
```

这里，您还可以添加其他事件监听器。例如，我们只需记录接收到的对象。根据需求，您可以添加一个额外的功能；如果需要，您甚至可以再次产生一个新事件以进行进一步处理。例如，您可以将事件产生到一家餐厅，该餐厅有一个新的预订请求，等等，通过一个管理餐厅通信的服务。

最后，我们可以使用 Spring Cloud Stream 库的`@EnableBinding`注解启用`bookingOrderInput`消息通道与流的绑定，并在`BillingApp.java`（`billing-service`模块的主类）中创建`EventListener`类的 bean，如下所示：

`BillingApp.java`可能看起来像这样：

```java
@SpringBootApplication(scanBasePackages = {"com.packtpub.mmj.billing", "com.packtpub.mmj.booking"}) 
@EnableBinding({BillingMessageChannels.class}) 
public class BillingApp { 

    public static void main(String[] args) { 
        SpringApplication.run(BillingApp.class, args); 
    } 

    @Bean 
    public EventListener eventListener() { 
        return new EventListener(); 
    } 
} 
```

现在，您可以启动账单微服务并发起一个新的`POST/v1/booking` REST 调用。您可以在账单微服务的日志中找到接收到的对象，如下所示：

```java
2017-10-02 20:22:17.728  INFO 6748 --- [           -C-1] c.p.m.b.d.s.WebSocketTweetReceiver       : Received BookingOrder: {"id": "999999999999", "name": "Test Booking 888", "userId": "3", "restaurantId": "1", "tableId": "1", "date": "2017-10-02", "time": "20:20:20.963543300"} 

```

# 参考文献

以下链接将为您提供更多信息：

+   **Apache Kafka**: [`kafka.apache.org/`](https://kafka.apache.org/)

+   **Apache Avro**: [`avro.apache.org/`](https://avro.apache.org/)

+   **Avro 规范**: [`avro.apache.org/docs/current/spec.html`](https://avro.apache.org/docs/current/spec.html)

+   **Spring Cloud Stream**: [`cloud.spring.io/spring-cloud-stream/`](https://cloud.spring.io/spring-cloud-stream/)

# 总结

在本章中，你学习了关于响应式微服务或基于事件的微服务。这些服务基于消息/事件工作，而不是基于 HTTP 的 REST 调用。它们提供了服务之间的异步通信，这种通信是非阻塞的，并且允许更好地利用资源和处理失败。

我们使用了 Apache Avro 和 Apache Kafka 与 Spring Cloud Stream 库来实现响应式微服务。我们在现有的`booking-service`模块中添加了代码，用于在 Kafka 主题下生产`amp.bookingOrdered`消息，并添加了新的模块`billing-service`来消费同一个事件。

你可能想要为生产者和消费者添加一个新事件。你可以为一个事件添加多个消费者，或者创建一个事件链作为练习。

在下一章中，你将学习如何根据认证和授权来保护微服务。我们还将探讨微服务安全的其他方面。
