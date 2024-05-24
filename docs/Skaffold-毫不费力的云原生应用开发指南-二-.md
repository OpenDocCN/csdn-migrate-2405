# Skaffold：毫不费力的云原生应用开发指南（二）

> 原文：[`zh.annas-archive.org/md5/12FE92B278177BC9DBE7FCBCECC73A83`](https://zh.annas-archive.org/md5/12FE92B278177BC9DBE7FCBCECC73A83)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：使用 Skaffold 容器映像构建器和部署器

在上一章中，我们深入研究了 Skaffold CLI 及其流水线阶段。我们还研究了 Skaffold 配置。在本章中，我们将通过创建一个 Reactive Spring Boot CRUD 应用程序来向您介绍响应式编程。然后，我们将了解 Skaffold 的可插拔架构，该架构支持不同的构建和部署容器映像到 Kubernetes 集群的方法。

在本章中，我们将涵盖以下主要主题：

+   创建一个 Reactive Spring Boot CRUD 应用程序

+   使用 Skaffold 容器映像构建器

+   探索 Skaffold 容器映像部署器

在本章结束时，您将对 Skaffold 支持的容器映像构建器（包括 Jib、Docker 和 Buildpacks）有了扎实的理解。您还将了解到 Helm、kubectl 和 Kustomize，这些工具由 Skaffold 支持，帮助您将容器化的应用程序部署到 Kubernetes。

# 技术要求

要跟随本章中的示例，您将需要以下内容：

+   Helm ([`helm.sh/docs/intro/install/`](https://helm.sh/docs/intro/install/))

+   Kustomize ([`kubectl.docs.kubernetes.io/installation/kustomize/`](https://kubectl.docs.kubernetes.io/installation/kustomize/))

+   Eclipse ([`www.eclipse.org/downloads/`](https://www.eclipse.org/downloads/)) 或 IntelliJ IDE ([`www.jetbrains.com/idea/download/`](https://www.jetbrains.com/idea/download/))

+   Git ([`git-scm.com/downloads`](https://git-scm.com/downloads))

+   Skaffold ([`skaffold.dev/docs/install/`](https://skaffold.dev/docs/install/))

+   Spring Boot 2.5

+   OpenJDK 16

+   minikube ([`minikube.sigs.k8s.io/docs/`](https://minikube.sigs.k8s.io/docs/)) 或 Docker Desktop for macOS 和 Windows ([`www.docker.com/products/dockerdesktop`](https://www.docker.com/products/dockerdesktop))

您可以从本书的 GitHub 存储库[`github.com/PacktPublishing/Effortless-Cloud-Native-App-Development-Using-Skaffold/tree/main/Chapter06`](https://github.com/PacktPublishing/Effortless-Cloud-Native-App-Development-Using-Skaffold/tree/main/Chapter06)下载本章的代码示例。

# 创建一个 Reactive Spring Boot CRUD 应用程序

为了演示使用 Skaffold 支持的各种容器镜像构建器，我们将创建一个简单的 Reactive Spring Boot `CRUD` REST 应用程序。当应用程序通过 curl 或 Postman 等 REST 客户端在本地访问时，我们会暴露一个名为`/employee`的 REST 端点，它将返回员工数据。

首先，为了建立一些上下文，让我们讨论一下构建应用程序的反应式方式。反应式编程（https://projectreactor.io/）是构建非阻塞应用程序的一种新方式，它是异步的、事件驱动的，并且需要少量线程来扩展。它们与典型的非反应式应用程序的另一个区别是，它们可以提供背压机制，以确保生产者不会压倒消费者。

Spring WebFlux 是一个反应式 Web 框架，是在 Spring 5 中引入的。Spring WebFlux 不需要 servlet 容器，可以在非阻塞容器（如 Netty 和 Jetty）上运行。我们需要添加`spring-boot-starter-webflux`依赖项来添加对 Spring WebFlux 的支持。使用 Spring MVC 时，我们有 Tomcat 作为默认的嵌入式服务器，而使用 WebFlux 时，我们得到 Netty。Spring WebFlux 控制器通常返回反应式类型，即 Mono 或 Flux，而不是集合或领域对象。

以下是将用于此 Spring Boot 应用程序的 Maven 依赖项：

![图 6.1 - Maven 依赖项](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_6.1_B17385.jpg)

图 6.1 - Maven 依赖项

让我们从应用程序的代码开始讲解：

1.  在这里，我们有一个包含五列的员工表：`id`、`first_name`、`last_name`、`age`和`salary`。`id`列是自动递增的。其他列遵循默认的蛇形命名方案。以下的`schema.sql` SQL 文件位于源代码目录中的`src/main/resources/schema.sql`路径下：

```
DROP TABLE IF EXISTS employee ;
CREATE TABLE employee ( id SERIAL PRIMARY KEY, first_name VARCHAR(100) NOT NULL,last_name VARCHAR(100) NOT NULL, age integer,salary decimal);
```

由于 H2 驱动程序位于类路径上，我们不必指定连接 URL，Spring Boot 会在应用程序启动时自动启动嵌入式 H2 数据库。

1.  为了在应用程序启动时初始化数据库架构，我们还需要注册`ConnectionFactoryInitializer`来获取`schema.sql`文件，如下面我们应用程序的主类所述。在这里，我们还保存了一些`Employee`实体，以便以后使用：

```
@SpringBootApplication
public class ReactiveApplication {
    private static final Logger logger =LoggerFactory.
      getLogger(ReactiveApplication.class);
    public static void main(String[] args) {
      SpringApplication.run(ReactiveApplication.class,
        args);
    }
    @Bean
    ConnectionFactoryInitializer initializer
      (ConnectionFactory connectionFactory) {
      ConnectionFactoryInitializer initializer = new
      ConnectionFactoryInitializer();
      initializer.setConnectionFactory
        (connectionFactory);
        initializer.setDatabasePopulator(new
        ResourceDatabasePopulator(new
        ClassPathResource("schema.sql")));
        return initializer;
    }
    @Bean
    CommandLineRunner init(EmployeeRepository
      employeeRepository) {
        return args -> {
            List<Employee> employees =  List.of(
                new Employee("Peter", "Parker", 25,
                      20000),
                new Employee("Tony", "Stark", 30,
                      40000),
                new Employee("Clark", "Kent", 31,
                      60000),
                new Employee("Clark", "Kent", 32,
                      80000),
                    new Employee("Bruce", "Wayne", 33,
                      100000)
            );
            logger.info("Saving employee " +
              employeeRepository.saveAll
                (employees).subscribe());
        };
    }
}
```

1.  使用 Spring Data R2DBC，您不必编写存储库接口的实现，因为它会在运行时为您创建一个实现。`EmployeeRepository`扩展了`ReactiveCrudRepository`，并继承了使用响应式类型保存、删除和查找员工实体的各种方法。以下是 CRUD 存储库：

```
import com.example.demo.model.Employee;
import org.springframework.data.repository.reactive.Reactive
  CrudRepository;
    public interface EmployeeRepository extends
      ReactiveCrudRepository<Employee,Long> {
}
```

以下是`EmployeeService`类：

```
import com.example.demo.model.Employee;
import com.example.demo.repository.EmployeeRepository;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
@Service
public class EmployeeService {
    private final EmployeeRepository 
      employeeRepository;
    public EmployeeService(EmployeeRepository
      employeeRepository) {
        this.employeeRepository = employeeRepository;
    }
    public Mono<Employee> createEmployee(Employee
      employee) {
        return employeeRepository.save(employee);
    }
    public Flux<Employee> getAllEmployee() {
        return employeeRepository.findAll();
    }
    public Mono<Employee> getEmployeeById(Long id) {
        return employeeRepository.findById(id);
    }
    public Mono<Void> deleteEmployeeById(Long id) {
        return employeeRepository.deleteById(id);
    }
}
```

1.  在以下 REST 控制器类中，您可以看到所有端点都返回 Flux 或 Mono 响应式类型：

```
import com.example.demo.model.Employee;
import com.example.demo.service.EmployeeService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
@RestController
@RequestMapping("/employee")
public class EmployeeController {
    private final EmployeeService employeeService;
    public EmployeeController(EmployeeService 
      employeeService) {
        this.employeeService = employeeService;
    }
    @GetMapping
    public Flux<Employee> getAllEmployee() {
        return employeeService.getAllEmployee();
    }
    @PostMapping
    public Mono<Employee> createEmployee(@RequestBody
      Employee employee) {
        return
          employeeService.createEmployee(employee);
    }
    @GetMapping("/{id}")
    public Mono<ResponseEntity<Employee>> 
      getEmployee(@PathVariable Long id) {
        Mono<Employee> employee =
          employeeService.getEmployeeById(id);
        return employee.map(e -> ResponseEntity.ok(e))
          .defaultIfEmpty(ResponseEntity.
            notFound().build());
    }
    @DeleteMapping("/{id}")
    public Mono<ResponseEntity<Void>> 
      deleteUserById(@PathVariable Long id) {
        return employeeService.deleteEmployeeById(id)
            .map(r ResponseEntity.ok().
               <Void>build())
            .defaultIfEmpty(ResponseEntity.notFound()
.              build());
    }
}
```

以下是`Employee`领域类：

```
public class Employee {
    @Id
    private Long id;
    private String firstName;
    private String lastName;
    private int age;
    private double salary;
    public Employee(String firstName, String lastName,
      int age, double salary) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.age = age;
        this.salary = salary;
    }
    public Long getId() {
        return id;
    }
    public void setId(Long id) {
        this.id = id;
    }
    public String getFirstName() {
        return firstName;
    }
    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }
    public String getLastName() {
        return lastName;
    }
    public void setLastName(String lastName) {
        this.lastName = lastName;
    }
    public int getAge() {
        return age;
    }
    public void setAge(int age) {
        this.age = age;
    }
    public double getSalary() {
        return salary;
    }
    public void setSalary(double salary) {
        this.salary = salary;
    }
}
```

1.  让我们使用`mvn spring-boot:run`命令运行此应用程序。一旦应用程序启动运行，您将看到以下日志：

```
2021-07-13 20:40:12.979  INFO 47848 --- [           main] com.example.demo.ReactiveApplication     : No active profile set, falling back to default profiles: default
2021-07-13 20:40:14.268  INFO 47848 --- [           main] .s.d.r.c.RepositoryConfigurationDelegate : Bootstrapping Spring Data R2DBC repositories in DEFAULT mode.
2021-07-13 20:40:14.379  INFO 47848 --- [           main] .s.d.r.c.RepositoryConfigurationDelegate : Finished Spring Data repository scanning in 102 ms. Found 1 R2DBC repository interfaces.
2021-07-13 20:40:17.627  INFO 47848 --- [           main] o.s.b.web.embedded.netty.NettyWebServer  : Netty started on port 8080
2021-07-13 20:40:17.652  INFO 47848 --- [           main] com.example.demo.ReactiveApplication     : Started ReactiveApplication in 5.889 seconds (JVM running for 7.979)
2021-07-13 20:40:17.921  INFO 47848 --- [           main] com.example.demo.ReactiveApplication     : Saving employee reactor.core.publisher.LambdaSubscriber@7dee835
```

访问`/employee` REST 端点后的输出如下：

![图 6.2 – REST 端点响应](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_6.2_B17385.jpg)

图 6.2 – REST 端点响应

在本节中，我们了解了响应式编程模型，并创建了一个响应式 Spring Boot CRUD 应用程序。在下一节中，我们将看看使用 Skaffold 将您的 Java 应用程序容器化的不同方法。

# 使用 Skaffold 容器镜像构建器

从*第三章*，*Skaffold – 简单易用的云原生 Kubernetes 应用开发*，我们知道 Skaffold 目前支持以下容器镜像构建器：

+   Dockerfile

+   Jib（Maven 和 Gradle）

+   Bazel

+   云原生 Buildpacks

+   自定义脚本

+   kaniko

+   Google Cloud Build

在本节中，我们将通过在上一节中构建的 Spring Boot 应用程序中详细介绍它们。让我们先谈谈 Dockerfile。

## Dockerfile

Docker 多年来一直是创建容器的黄金标准。即使今天有许多 Docker 的替代品，但它仍然活跃。Docker 架构依赖于必须运行以服务所有 Docker 命令的守护进程。然后有一个 Docker CLI，它将命令发送到 Docker 守护进程以执行。守护进程执行所需的操作，如推送、拉取、运行容器镜像等。Docker 期望一个名为 Dockerfile 的文件，由您手动编写，其中包含它理解的步骤和指令。然后使用诸如`docker build`之类的命令使用此 Dockerfile 创建应用程序的容器镜像。这里的优势在于，这允许根据您的需求对应用程序的容器镜像进行不同的定制级别。

要使用 Docker 构建镜像，我们需要向 Dockerfile 添加一些指令。这些指令作为输入，然后 Docker 守护进程使用这些指令创建镜像。让我们看一个示例，以了解典型 Dockerfile 用于 Java 应用程序的工作原理。

![图 6.3 – Docker 构建流程](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_6.3_B17385.jpg)

图 6.3 – Docker 构建流程

我们将使用以下 Dockerfile 来容器化我们的应用程序：

```
FROM openjdk:16
COPY target/*.jar app.jar
ENTRYPOINT ["java","-jar","/app.jar"]
```

从上述代码块中，我们可以看到以下内容：

+   `FROM`指令表示我们应用程序的基础镜像。

+   `COPY`指令，顾名思义，将由 Maven 构建的本地.jar 文件复制到我们的镜像中。

+   `ENTRYPOINT`指令在容器启动时充当可执行文件。

在`skaffold.yaml`文件中，我们添加了一个名为`docker`的新配置文件。以下是`docker`配置文件的相关部分：

```
profiles:
  - name: docker
    build:
      artifacts:
        - image: reactive-web-app
      local: {}
```

我们可以使用`skaffold dev –profile=docker`命令运行构建。输出应该与我们之前在*图 6.2*中看到的类似。

## Jib

**Jib** (https://github.com/GoogleContainerTools/jib)代表**Java Image Builder**，纯粹由 Java 编写。您已经知道 Jib 允许 Java 开发人员使用诸如 Maven 和 Gradle 之类的构建工具构建容器。但是，它还有一个 CLI 工具，可用于非 Java 应用程序，如 Python 或 Node.js。

使用 Jib 的重要优势是您无需了解安装 Docker 或维护 Dockerfile 的任何内容。要使您的 Java 应用程序容器化，您无需阅读无数的 Docker 教程。Jib 是无守护进程的。此外，作为 Java 开发人员，我们只关心构件（即 jar 文件），并且使用 Jib，我们不必处理任何 Docker 命令。使用 Jib，Java 开发人员可以将插件添加到他们选择的构建工具（Maven/Gradle）中，并且只需进行最少的配置，即可使应用程序容器化。Jib 将您的应用程序源代码作为输入，并输出您的应用程序的容器镜像。以下是使用 Jib 构建您的 Java 应用程序的流程：

![图 6.4 – Jib 构建流程](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_6.4_B17385.jpg)

图 6.4 – Jib 构建流程

让我们尝试使用 Jib 构建上一节中创建的应用程序：

1.  首先，我们将使用 Skaffold 的`init`命令创建`skaffold.yaml`文件，如下所示：

```
apiVersion: skaffold/v2beta20
kind: Config
metadata:
  name: reactive-web-app
build:
  artifacts:
  - image: reactive-web-app
    jib:
      fromImage: adoptopenjdk:16-jre
      project: com.example:reactive-web-app
      args:
        - -DskipTests
deploy:
  kubectl:
    manifests:
    - k8s/manifest.yaml
```

提示

Jib 巧妙地将应用程序图像层分成以下几个部分，以加快重建速度：

-类

-资源

-项目依赖项

-快照和所有其他依赖项

目标是将经常更改的文件与很少更改的文件分开。直接的好处是，您不必重建整个应用程序，因为 Jib 只重新构建包含更改文件的层，并重用未更改文件的缓存层。

使用 Jib，如果您不指定镜像摘要，您可能会在日志中看到以下警告：

[警告] 基础镜像 `'adoptopenjdk/openjdk16'` 没有使用特定的镜像摘要 - 构建可能不可重现。

您可以通过使用正确的镜像摘要来克服这一点。例如，在 `maven-jib-plugin` 中，您可以进行以下更改，而在 `skaffold.yaml` 文件中，您可以指定镜像摘要：

`<plugin>`

`<groupId>com.google.cloud.tools</groupId>`

`<artifactId>jib-maven-plugin</artifactId>`

`<version>3.1.1</version>`

`<configuration>`

      <from>

`<image>adoptopenjdk/openjdk16@           sha256:b40f81a9f7e7e4533ed0c` `           6ac794ded9f653807f757e2b8b4e1            fe729b6065f7f5</image>`

      </from>

      <to>

`<image>docker.io/hiashish/image</image>`

      </to>

`</configuration>`

`</plugin>`

以下是 Kubernetes 服务清单：

```
apiVersion: v1
kind: Service
metadata:
  name: reactive-web-app
spec:
  ports:
    - port: 8080
      protocol: TCP
      targetPort: 8080
  type: Loadbalancer
  selector:
    app: reactive-web-app
```

以下是 Kubernetes 部署清单：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: reactive-web-app
spec:
  selector:
    matchLabels:
      app: reactive-web-app
  template:
    metadata:
      labels:
        app: reactive-web-app
    spec:
      containers:
        - name: reactive-web-app
          image: reactive-web-app
```

1.  现在，我们必须运行 `skaffold dev` 命令。以下是输出：

```
skaffold dev
Listing files to watch...
 - reactive-web-app
Generating tags...
 - reactive-web-app -> reactive-web-app:fcda757-dirty
Checking cache...
 - reactive-web-app: Found Locally
Starting test...
Tags used in deployment:
 - reactive-web-app -> reactive-web-app:3ad471bdebe8e0606040300c9b7f1af4bf6d0a9d014d7cb62d7ac7b884dcf008
Starting deploy...
 - service/reactive-web-app created
 - deployment.apps/reactive-web-app created
Waiting for deployments to stabilize...
 - deployment/reactive-web-app is ready.
Deployments stabilized in 3.34 seconds
Press Ctrl+C to exit
Watching for changes...
```

使用 `minikube service reactive-web-app` 命令可以在 minikube 中打开暴露的服务。我们将使用以下截图中提到的 URL 来访问我们的应用程序：

![图 6.5 - 暴露的服务 URL](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_6.5_B17385.jpg)

图 6.5 - 暴露的服务 URL

访问 `http://127.0.0.1:55174/employee` URL 后，我们应该得到类似于 *图 6.2* 的输出。

## Bazel

Bazel 是一个类似于 Maven 和 Gradle 的开源、多语言、快速和可扩展的构建工具。Skaffold 支持 Bazel，并且可以将镜像加载到本地 Docker 守护程序中。Bazel 需要两个文件：`WORKSPACE` 和 `BUILD`。

`WORKSPACE` 文件通常位于项目的根目录。此文件指示 Bazel 工作区。它查找构建输入，并将构建输出存储在创建 `WORKSPACE` 文件的目录中。

`BUILD`文件指示 Bazel 要构建什么以及如何构建项目的不同部分。以下是一个 Java 应用程序的`BUILD`文件示例。在这个例子中，我们指示 Bazel 使用`java_binary`规则为我们的应用程序创建一个`.jar`文件：

```
java_binary(    
name = "ReactiveWebApp",    
srcs = glob(["src/main/java/com/example/*.java"]),)
```

要构建您的项目，您可以运行诸如`build //: ReactiveWebApp`之类的命令。以下是包含`bazel`配置文件的`skaffold.yaml`文件：

```
profiles:
  - name: bazel
    build:
      artifacts:
        - image: reactive-web-app
          bazel:
            target: //:reactive-web-app.tar
```

接下来我们有 Buildpacks。

## Buildpacks

Heroku 在 2011 年首次创建了 Buildpacks（[`buildpacks.io/`](https://buildpacks.io/)）。它现在是 CNCF 基金会的一部分。就像 Jib 一样，Buildpacks 也可以在不需要 Dockerfile 的情况下工作。但是，您需要一个正在运行的 Docker 守护程序进程才能使其工作。使用 Buildpacks，输入是您的应用程序源代码，输出是容器镜像。在这方面，它与 Jib 非常相似，尽管 Jib 可以在没有 Docker 守护程序的情况下工作。

在后台，Buildpacks 做了很多工作，包括检索依赖项，处理资产，处理缓存以及为应用程序使用的任何语言编译代码：

![图 6.6 - Buildpacks 构建流程](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_6.6_B17385.jpg)

图 6.6 - Buildpacks 构建流程

正如前面所解释的，Skaffold 需要一个本地的 Docker 守护程序来使用 Buildpacks 构建镜像。Skaffold 将在容器内部使用`skaffold.yaml`文件中 Buildpacks 配置中指定的构建器执行构建。此外，您不必安装 pack CLI，因为 Google Cloud Buildpacks 项目（[`github.com/GoogleCloudPlatform/buildpacks`](https://github.com/GoogleCloudPlatform/buildpacks)）提供了用于工具如 Skaffold 的构建器镜像。您可以选择跳过此步骤，但在成功构建后，Skaffold 将把镜像推送到远程注册表。

提示

从 Spring Boot 2.3 版本开始，Spring Boot 直接支持 Maven 和 Gradle 项目的 Buildpacks。使用`mvn spring-boot:build-image`命令，您可以创建一个加载到本地运行的 Docker 守护程序的应用程序镜像。虽然您不需要维护 Dockerfile，但 Buildpacks 依赖于 Docker 守护程序进程。如果您在本地没有运行 Docker 守护程序，执行 Maven 命令时将会收到以下错误：

“无法执行目标 org.springframework.boot:spring-boot-maven-plugin:2.4.2:build-image (default-cli) on project imagebuilder: Execution default-cli of goal org.springframework.boot:spring-boot-maven-plugin:2.4.2:build-image failed: Connection to the Docker daemon at 'localhost' failed with error "[61] Connection refused"; ensure the Docker daemon is running and accessible”

为了使用 Buildpacks 构建我们的应用程序，我们添加了一个名为`pack`的新配置文件，并将其用于向`skaffold.yaml`配置文件的`build`部分添加一个新的部分。在`builder`字段中，我们指示 Skaffold 使用`gcr.io/buildpacks/builder:v1`构建器映像。以下是配置文件的相关部分：

```
profiles:
  - name: pack
    build:
      artifacts:
        - image: reactive-web-app
          buildpacks:
            builder: gcr.io/buildpacks/builder:v1
            env:
              - GOOGLE_RUNTIME_VERSION=16
```

我们可以使用`skaffold dev –profile=pack`命令运行构建。输出应该类似于我们在*图 6.2*中看到的。

提示

Spring Boot Buildpacks 集成可用于将映像推送到远程容器注册表。我们需要在`pom.xml`中进行以下更改：

```
<plugin>
    <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-maven-plugin</artifactId>
    <configuration>
        <image>
           <name>docker.example.com/library/$
            {project.artifactId}</name>
           <publish>true</publish>
        </image>
        <docker>
          <publishRegistry>
            <username>user</username>
            <password>secret</password>
            <url>https://docker.example.com/v1/</url>
            <email>user@example.com</email>
            </publishRegistry>
        </docker>
    </configuration>
</plugin>
```

## 自定义脚本

如果没有支持的容器映像构建器适用于您的用例，您可以使用自定义脚本选项。通过此选项，您可以编写自定义脚本或选择您喜欢的构建工具。您可以通过在`skaffold.yaml`文件的构建部分的每个相应构件中添加一个自定义字段来配置自定义脚本。

在下面的示例`skaffold.yaml`文件中，我们创建了一个名为`custom`的新配置文件。在`buildCommand`字段中，我们使用`build.sh`脚本来将我们的 Spring Boot 应用程序容器化：

```
 profiles:
  - name: custom
    build:
      artifacts:
        - image: reactive-web-app
          custom:
            buildCommand: sh build.sh
```

`build.sh`脚本文件包含以下内容。它使用`docker build`命令来创建我们应用程序的映像。Skaffold 将提供`$IMAGE`（即完全限定的映像名称环境变量）给自定义构建脚本：

```
#!/bin/sh
set -e
docker build -t "$IMAGE" .
```

接下来我们转向 kaniko。

## kaniko

kaniko 是一个开源工具，用于在容器或 Kubernetes 集群内部从 Dockerfile 构建容器映像。kaniko 不需要特权根访问权限来构建容器映像。

kaniko 不依赖于 Docker 守护程序，并在用户空间完全执行 Dockerfile 中的每个命令。使用 kaniko，您可以在无法安全运行 Docker 守护程序的环境中开始构建容器映像，例如标准 Kubernetes 集群。那么，kaniko 是如何工作的呢？嗯，kaniko 使用一个名为`gcr.io/kaniko-project/executor`的执行器映像，该映像在容器内运行。不建议在另一个映像中运行 kaniko 执行器二进制文件，因为它可能无法正常工作。

让我们看看这是如何完成的：

1.  我们将使用以下 Dockerfile 与 kaniko 构建应用程序的容器映像：

```
FROM maven:3-adoptopenjdk-16 as build
RUN mkdir /app
COPY . /app
WORKDIR /app
RUN mvn clean verify -DskipTests
FROM adoptopenjdk:16-jre
RUN mkdir /project
COPY --from=build /app/target/*.jar /project/app.jar
WORKDIR /project
ENTRYPOINT ["java","-jar","app.jar"]
```

1.  以下是`skaffold.yaml`的相关部分：

```
profiles:
  - name: kaniko
    build:
      cluster:
        pullSecretPath: /Users/ashish/Downloads/kaniko-secret.json
      artifacts:
        - image: reactive-web-app
          kaniko: {}
```

在这里，我们添加了一个名为`kaniko`的新配置文件，以在 Google Kubernetes 集群中构建我们的容器映像。您将在*第八章*中了解更多关于 GKE 的信息，*使用 Skaffold 将 Spring Boot 应用部署到 Google Kubernetes Engine*。

`skaffold.yaml`文件中需要强调的一个重要点是，我们需要从活动的 Kubernetes 集群获取凭据，以便在集群内构建我们的映像。为此，需要一个 GCP 服务帐户。此帐户具有存储管理员角色，以便可以拉取和推送映像。我们可以使用以下命令构建并将应用程序部署到 GKE：

```
skaffold run --profile=kaniko --default-repo=gcr.io/basic-curve-316617
```

我们将在 GCP 上托管的远程 Kubernetes 集群上进行演示。让我们开始吧：

1.  首先，我们需要为 kaniko 创建一个服务帐户，该帐户具有从`gcr.io`拉取和推送映像的权限。然后，我们需要下载 JSON 服务帐户文件并将文件重命名为`kaniko-secret`。还要确保不要在文件名后添加`.json`；使用以下命令创建 Kubernetes 密钥。您需要确保 Kubernetes 上下文设置为远程 Kubernetes 集群：

```
kubectl create secret generic kaniko-secret --from-file=kaniko-secret
```

1.  由于我们将把映像推送到**Google 容器注册表**（**GCR**），我们已经提到了`--default-repo`标志，以便它始终指向 GCR。以下是日志：

```
Generating tags...
 - reactive-web-app -> gcr.io/basic-curve-316617/reactive-web-app:fcda757-dirty
Checking cache...
 - reactive-web-app: Not found. Building
Starting build...
Checking for kaniko secret [default/kaniko-secret]...
Creating kaniko secret [default/kaniko-secret]...
Building [reactive-web-app]...
INFO[0000] GET KEYCHAIN                                 
INFO[0000] running on kubernetes ....
```

在以下日志中，您可以看到 kaniko 开始在容器内构建映像，下载不同构建阶段的基础映像。kaniko 开始打包和下载我们的 Spring Boot 应用程序的依赖项：

```
INFO[0001] Retrieving image manifest adoptopenjdk:16-jre 
INFO[0001] Retrieving image adoptopenjdk:16-jre from registry index.docker.io 
INFO[0001] GET KEYCHAIN
INFO[0001] Built cross stage deps: map[0:[/app/target/*.jar]] 
INFO[0001] Retrieving image manifest maven:3-adoptopenjdk-16 
...............
INFO[0035] RUN mvn clean verify -DskipTests             
INFO[0035] cmd: /bin/sh                                 
INFO[0035] args: [-c mvn clean verify -DskipTests]      
INFO[0035] Running: [/bin/sh -c mvn clean verify -DskipTests] 
[INFO] Scanning for projects...
Downloading from central: https://repo.maven.apache.org/maven2/org/springframework/boot/spring-boot-starter-parent/2.5.2/spring-boot-starter-parent-2.5.2.pom
```

1.  在以下日志中，您可以看到构建成功，并且 kaniko 能够将映像推送到 GCR。然后，我们使用`kubectl`将映像部署到 Google Kubernetes 集群：

```
[INFO] BUILD SUCCESS
INFO[0109] Taking snapshot of full filesystem...        
INFO[0114] Saving file app/target/reactive-web-app-0.0.1-SNAPSHOT.jar for later use 
....        
INFO[0130] COPY --from=build /app/target/*.jar /project/app.jar    
....        
INFO[0131] ENTRYPOINT ["java","-jar","app.jar"]
INFO[0131] GET KEYCHAIN                                 
INFO[0131] Pushing image to gcr.io/basic-curve-316617/reactive-web-app:fcda757-dirty 
INFO[0133] Pushed image to 1 destinations               
Starting test...
Tags used in deployment:
 - reactive-web-app -> gcr.io/basic-curve-316617/reactive-web-app:fcda757-dirty@9797e8467bd25fa4a237 e21656cd574c0c46501e5b3233a1f27639cb5b66132e
Starting deploy...
 - service/reactive-web-app created
 - deployment.apps/reactive-web-app created
Waiting for deployments to stabilize...
 - deployment/reactive-web-app: creating container reactive-web-app
    - pod/reactive-web-app-6b885dcf95-q8dr5: creating container reactive-web-app
 - deployment/reactive-web-app is ready.
Deployments stabilized in 12.854 seconds
```

在以下截图中，我们可以看到部署后，一个 pod 正在运行，并且暴露的服务是**Load balancer**类型：

![图 6.7 – Pod 运行和服务暴露给外部访问](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_6.7_B17385.jpg)

图 6.7 – Pod 运行和服务暴露给外部访问

访问我们的 Spring Boot 应用程序的`/employee` REST 端点后，使用 GKE 公开的端点的输出如下：

![图 6.8 – REST 应用程序响应](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_6.8_B17385.jpg)

图 6.8 – REST 应用程序响应

## Google Cloud Build

Cloud Build 是一个使用 GCP 基础设施运行构建的服务。Cloud Build 通过从各种存储库或 Google Cloud Storage 空间导入源代码，执行构建，并生成容器镜像等工件来工作。

我们在`skaffold.yaml`中创建了一个名为`gcb`的新配置文件，以使用 Google Cloud Build 触发我们应用程序的远程构建。以下是`skaffold.yaml`配置文件部分的相关部分：

```
profiles:
  - name: gcb
    build:
      artifacts:
        - image: reactive-web-app
          docker:
            cacheFrom:
              - reactive-web-app
      googleCloudBuild: {}
```

我们可以运行以下命令来开始使用 Google Cloud Build 远程构建我们的应用程序：

```
skaffold run --profile=gcb --default-repo=gcr.io/basic-curve-316617
```

如果这是您第一次这样做，请确保已经从**Cloud Console**仪表板或通过 gcloud CLI 启用了 Cloud Build API。否则，您可能会收到以下错误：

```
Generating tags...
 - reactive-web-app -> gcr.io/basic-curve-316617/reactive-web-app:fcda757-dirty
Checking cache...
 - reactive-web-app: Not found. Building
Starting build...
Building [reactive-web-app]...
Pushing code to gs://basic-curve-316617_cloudbuild/source/basic-curve-316617-046b951c-5062-4824-963b-a204302a77e1.tar.gz
could not create build: googleapi: Error 403: Cloud Build API has not been used in project 205787228205 before or it is disabled. Enable it by visiting https://console.developers.google.com/apis/api/cloudbuild.googleapis.com/overview?project=205787228205 then retry. If you enabled this API recently, wait a few minutes for the action to propagate to our systems and retry.
.....
```

您可以通过访问错误日志中提到的 URL 并单击**ENABLE**按钮来通过**Cloud Console**仪表板启用 Cloud Build API，如下截图所示：

![图 6.9 – 启用 Cloud Build API](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_6.9_B17385.jpg)

图 6.9 – 启用 Cloud Build API

在运行实际命令启动构建和部署过程之前，您需要确保在您的`kubeconfig`文件中，GKE 远程集群是此部署的活动集群。以下是`skaffold run`命令的输出。在以下日志中，您可以看到我们的整个源代码被打包为`tar.gz`文件并发送到 Google Cloud Storage 位置。然后，Cloud Build 会获取它并开始构建我们的镜像：

```
skaffold run --profile=gcb --default-repo=gcr.io/basic-curve-316617
Generating tags...
 - reactive-web-app -> gcr.io/basic-curve-316617/reactive-web-app:fcda757-dirty
Checking cache...
 - reactive-web-app: Not found. Building
Starting build...
Building [reactive-web-app]...
Pushing code to gs://basic-curve-316617_cloudbuild/source/basic-curve-316617-aac889cf-d854-4e7f-a3bc-b26ea06bf854.tar.gz
Logs are available at 
https://console.cloud.google.com/m/cloudstorage/b/basic-curve-316617_cloudbuild/o/log-43705458-0f75-4cfd-8532-7f7db103818e.txt
starting build "43705458-0f75-4cfd-8532-7f7db103818e"
FETCHSOURCE
Fetching storage object: gs://basic-curve-316617_cloudbuild/source/basic-curve-316617-aac889cf-d854-4e7f-a3bc-b26ea06bf854.tar.gz#1626576177672677
Copying gs://basic-curve-316617_cloudbuild/source/basic-curve-316617-aac889cf-d854-4e7f-a3bc-b26ea06bf854.tar.gz#1626576177672677...
- [1 files][ 42.2 MiB/ 42.2 MiB]                                                
Operation completed over 1 objects/42.2 MiB.                                     
BUILD
Starting Step #0
Step #0: Already have image (with digest): gcr.io/cloud-builders/docker
…
```

在以下日志中，您可以看到镜像已经构建、标记并推送到 GCR。然后，使用`kubectl`，应用程序被部署到 GKE，如下所示：

```
Step #1: Successfully built 1a2c04528dad
Step #1: Successfully tagged gcr.io/basic-curve-316617/reactive-web-app:fcda757-dirty
Finished Step #1
PUSH
Pushing gcr.io/basic-curve-316617/reactive-web-app:fcda757-dirty
The push refers to repository [gcr.io/basic-curve-316617/reactive-web-app]
7a831de44071: Preparing
574a11c0c1c8: Preparing
783bfc5acd81: Preparing
2da4fab53cd6: Preparing
a70daca533d0: Preparing
783bfc5acd81: Layer already exists
2da4fab53cd6: Layer already exists
a70daca533d0: Layer already exists
574a11c0c1c8: Pushed
7a831de44071: Pushed
fcda757-dirty: digest: sha256:22b2de72d3e9551f2531f2b9dcdf5e4b2eabaabc9d1c7a5930bcf226e6b9c04b size: 1372
DONE
Starting test...
Tags used in deployment:
 - reactive-web-app -> gcr.io/basic-curve-316617/reactive-web-app:fcda757-dirty@sha256:22b2de72d3e9551f2531f2b9dcdf5e4b2 eabaabc9d1c7a5930bcf226e6b9c04b
Starting deploy...
 - service/reactive-web-app configured
 - deployment.apps/reactive-web-app created
Waiting for deployments to stabilize...
 - deployment/reactive-web-app: creating container reactive-web-app
    - pod/reactive-web-app-789f775d4-z998t: creating container reactive-web-app
 - deployment/reactive-web-app is ready.
Deployments stabilized in 1 minute 51.872 seconds
```

在 GKE 的**Workload**部分，您可以看到**reactive-web-app**已经部署，并且其状态为 OK，如下所示：

![图 6.10 – 应用程序成功部署在 GKE 上](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_6.10_B17385.jpg)

图 6.10 - 应用程序成功部署在 GKE 上

在本节中，我们学习了如何以不同的方式将我们的 Reactive Spring Boot CRUD 应用程序容器化。

在下一节中，我们将探讨使用 Skaffold 将应用程序部署到 Kubernetes 的不同方法。

# 探索 Skaffold 容器镜像部署程序

在本节中，我们将看看 Skaffold 支持的容器镜像部署方法。使用 Skaffold，您可以使用以下三种工具将应用程序部署到 Kubernetes：

+   Helm

+   kubectl

+   Kustomize

让我们详细讨论一下。

## Helm

**Helm**是软件包管理器，**charts**是您的 Kubernetes 应用程序的软件包。它允许您轻松定义、安装和更新您的 Kubernetes 应用程序。您可以为您的应用程序编写图表，或者从稳定的图表存储库中使用用于流行软件（如 MySQL 和 MongoDB）的生产就绪的预打包图表。

直到 Helm 2，Helm 遵循客户端-服务器架构。然而，由于 Helm 3 对架构进行了重大更改，它是一个仅客户端的架构。因此，在您的 Kubernetes 集群上不需要安装**Tiller**等服务器端组件。

现在，让我们更多地了解 Helm：

1.  Skaffold 不会为我们安装 Helm，因此我们必须使用 macOS 的 Homebrew 软件包管理器进行安装：

```
$ brew install helm
$ helm version
version.BuildInfo{Version:"v3.6.3", GitCommit:"d506314abfb5d21419df8c7e7e68012379db2354", GitTreeState:"dirty", GoVersion:"go1.16.5"}
```

对于 Windows，您可以使用 chocolatey 进行下载：

```
choco install kubernetes-helm
```

您还可以使用安装程序脚本下载 Helm，该脚本将下载最新版本：

```
$ curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3
$ chmod 700 get_helm.sh
$ ./get_helm.sh
```

1.  接下来，我们将使用以下命令创建 Helm 图表骨架：

```
$ helm create reactive-web-app-helm             
Creating charts
```

1.  我们将创建一个名为`jibWithHelm`的新 Skaffold 配置文件，以使用 Jib 构建图像，然后使用 Helm 部署它：

```
profiles:
    - name: jibWithHelm
    build:
      artifacts:
        - image: gcr.io/basic-curve-316617/reactive-
            web-app-helm
          jib:
            args:
              - -DskipTests
    deploy:
      helm:
        releases:
          - name: reactive-web-app-helm
            chartPath: reactive-web-app-helm
            artifactOverrides:
              imageKey: gcr.io/basic-curve-
                316617/reactive-web-app-helm
            valuesFiles:
              - reactive-web-app-helm/values.yaml
            imageStrategy:
              helm: { }
```

在`build`部分下的图像名称应与`skaffold.yaml`文件的`artifactOverrides`部分下给定的图像名称匹配。否则，将会出现错误。

我们还在`skaffold.yaml`文件的`valuesFiles`部分提供了指向`values.yaml`文件的路径。

使用 Helm 定义图像引用的典型约定是通过`values.yaml`文件。以下是将由 Helm 引用的`values.yaml`文件的内容：

```
replicaCount: 1
imageKey:
  repository: gcr.io/basic-curve-316617
  pullPolicy: IfNotPresent
  tag: latest
service:
  type: LoadBalancer
  port: 8080
  targetPort: 8080
```

`values.yaml`文件中的值将在模板化资源文件中被引用，如下面的代码片段所示。此模板文件位于`reactive-web-app-helm/templates/**.yaml`中：

```
    spec:
      containers:
        - name: {{ .Chart.Name }}
          image: {{ .Values.imageKey.repository }}:{{ 
            .Values.imageKey.tag }}
          imagePullPolicy: {{ .Values.imageKey.pullPolicy }}
```

运行`skaffold run --profile=jibWithHelm`后，Skaffold 将使用 Jib 构建图像，并使用 Helm 图表将其部署到 GKE。这将导致以下输出：

```
skaffold run --profile=jibWithHelm
Generating tags...
 - gcr.io/basic-curve-316617/reactive-web-app-helm -> gcr.io/basic-curve-316617/reactive-web-app-helm:3ab62c6-dirty
Checking cache...
 - gcr.io/basic-curve-316617/reactive-web-app-helm: Found Remotely
Starting test...
Tags used in deployment:
 - gcr.io/basic-curve-316617/reactive-web-app-helm -> gcr.io/basic-curve-316617/reactive-web-app-helm:3ab62c6-dirty@sha256:2d9539eb23bd9db578feae7e4956c30d9320786217a7307e0366d9cc5ce359bc
Starting deploy...
Helm release reactive-web-app-helm not installed. Installing...
NAME: reactive-web-app-helm
LAST DEPLOYED: Thu Aug 26 11:34:39 2021
NAMESPACE: default
STATUS: deployed
REVISION: 1
Waiting for deployments to stabilize...
 - deployment/reactive-web-app-helm is ready.
Deployments stabilized in 3.535 seconds
```

我们可以通过转到 GKE 的**工作负载**部分来验证 pod 是否正在运行。在下面的截图中，我们可以看到我们有一个正在运行的 pod：

图 6.11 - Helm 图表在 GKE 上成功部署

](image/Figure_6.11_B17385.jpg)

图 6.11 - Helm 图表在 GKE 上成功部署

同样，在**服务和入口**部分下，我们可以看到已经为外部访问暴露了一个**外部负载均衡器**类型的服务：

![图 6.12 - 在 GKE 上暴露的 LoadBalancer 服务类型](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_6.12_B17385.jpg)

图 6.12 - 在 GKE 上暴露的 LoadBalancer 服务类型

在**Endpoints**列中使用 URL 访问应用程序后，输出应该类似于我们在*图 6.2*中看到的。

## kubectl

kubectl 是一个命令行工具，用于在 Kubernetes 集群上运行命令。它与 Kubernetes API 服务器交互以运行这些命令。您可以使用它来完成各种任务，例如查看 pod 的日志，创建 Kubernetes

例如部署资源，了解集群的状态和 pod 等。在下面的代码片段中，您可以看到我们正在使用 kubectl 进行部署。Kubernetes 清单位于`k8s`目录下：

```
deploy:
  kubectl:
    manifests:
    - k8s/manifest.yaml
```

## Kustomize

Kustomize，顾名思义，是一种无模板的声明性方法，用于 Kubernetes 配置、管理和自定义选项。使用 Kustomize，我们提供一个基本的框架和补丁。在这种方法中，与 Helm 相比，我们提供一个基本的部署，然后描述不同环境的差异。例如，我们可以在生产环境和暂存环境中有不同数量的副本和健康检查。Kustomize 可以单独安装，自 kubectl 的 1.14 版本以来，我们可以使用`-k`命令。请按照[`kubectl.docs.kubernetes.io/installation/kustomize/`](https://kubectl.docs.kubernetes.io/installation/kustomize/)中提到的说明在支持的操作系统上安装它。

在下面的例子中，我们有一个名为`kustomizeProd`的配置文件，并且正在使用 Kustomize 作为我们应用的部署策略：

```
 profiles:  
  - name: kustomizeProd
    build:
      artifacts:
        - image: reactive-web-app
          jib:
            args:
              - -DskipTests
    deploy:
      kustomize:
        paths:
          - kustomization/overlays/prod
```

为了使 Kustomize 正常工作，我们必须具有以下目录结构。在下面的目录中，您可以看到在`kustomization/base`目录下，我们有描述我们想要在 GKE 集群中部署的资源的原始 YAML 文件。我们永远不会触及这些文件；相反，我们只会在它们之上应用定制来创建新的资源定义：

```
├── kustomization
│   ├── base
│   │   ├── deployment.yaml
│   │   ├── kustomization.yaml
│   │   └── service.yaml
│   └── overlays
│       ├── dev
│       │   ├── environment.yaml
│       │   └── kustomization.yaml
│       └── prod
│           ├── increase_replica.yaml
│           ├── kustomization.yaml
│           └── resources_constraint.yaml
```

我们在`base`文件夹中有一个名为`kustomization.yaml`的文件。它描述了您使用的资源。这些资源是相对于当前文件的 Kubernetes 清单文件的路径：

```
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yaml
  - service.yaml 
```

接下来，我们有`kustomization/overlays/prod`文件夹，其中包含一个`kustomization.yaml`文件。它包含以下内容：

```
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base
patchesStrategicMerge:
  - increase_replica.yaml
  - resources_constraint.yaml
```

如果您能看到，在`base`中，我们没有定义任何环境变量、副本数或资源约束。但是对于生产场景，我们必须在我们的基础之上添加这些内容。为此，我们只需创建我们想要应用在我们的基础之上的 YAML 块，并在`kustomization.yaml`文件中引用它。我们已经将这个 YAML 添加到`kustomization.yaml`文件中的`patchesStrategicMerge`列表中。

`increase_replica.yaml`文件包含两个副本，内容如下：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: reactive-web-app
spec:
  replicas: 2
```

`resources_constraint.yaml`文件包含资源请求和限制，内容如下：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: reactive-web-app
spec:
  template:
    spec:
      containers:
        - name: reactive-web-app
          resources:
            requests:
              memory: 512Mi
              cpu: 256m
            limits:
              memory: 1Gi
              cpu: 512m
```

现在，我们可以运行`skaffold run --profile=kustomizeProd --default-repo=gcr.io/basic-curve-316617`命令。这将使用 Kustomize 将应用程序部署到 GKE。我们得到的输出应该与我们之前在*图 6.2*中看到的类似。

在本节中，我们看了一下我们可以使用 Skaffold 来将应用程序部署到 Kubernetes 集群的工具。

# 总结

在本章中，我们首先介绍了响应式编程，并构建了一个 Spring Boot CRUD 应用程序。我们还介绍了 Skaffold 支持的容器镜像构建工具，包括 Docker、kaniko、Jib 和 Buildpacks。我们通过实际实现来了解了它们。我们还讨论了使用诸如 kubectl、Helm 和 Kustomize 等工具将镜像部署到 Kubernetes 集群的不同方式。

在本章中，我们对诸如 Jib、kaniko、Helm 和 Kustomize 等工具有了扎实的了解。您可以运用这些工具的知识来构建和部署您的容器。

在下一章中，我们将使用 Google 的 Cloud Code 扩展构建和部署一个 Spring Boot 应用程序到 Kubernetes。

# 进一步阅读

要了解更多关于 Skaffold 的信息，请查看 Skaffold 文档：[`skaffold.dev/docs/`](https://skaffold.dev/docs/)。


# 第三部分：使用 Skaffold 构建和部署云原生 Spring Boot 应用程序

本节将主要关注使用 Skaffold 构建和部署 Spring Boot 应用程序到本地（minikube 等）和远程集群（GKE）的过程。我们将探讨如何在舒适的 IDE 环境中使用 Google 开发的 Cloud Code 构建和部署云原生应用程序。然后，我们将使用 Skaffold 构建和部署 Spring Boot 应用程序到像 GKE 这样的托管 Kubernetes 平台。我们还将学习如何使用 Skaffold 和 GitHub Actions 创建一个生产就绪的 CI/CD 流水线。我们将通过结合 Skaffold 和 Argo CD 来实现 GitOps 风格的 CD 工作流进行一些实验。最后，我们将探讨一些 Skaffold 的替代方案，并了解我们在工作流中应该利用的 Skaffold 最佳实践。此外，我们将探讨使用 Skaffold 开发应用程序时最常见的陷阱和限制。最后，我们将总结本书学到的内容。

在本节中，我们有以下章节：

+   [*第七章*]，*使用 Cloud Code 插件构建和部署 Spring Boot 应用程序*

+   [*第八章*]，*使用 Skaffold 将 Spring Boot 应用程序部署到 Google Kubernetes Engine*

+   [*第九章*]，*使用 Skaffold 创建生产就绪的 CI/CD 流水线*

+   [*第十章*]，*探索 Skaffold 的替代方案、最佳实践和陷阱*


# 第七章：使用 Cloud Code 插件构建和部署 Spring Boot 应用程序

在上一章中，我们了解了 Skaffold 支持的容器镜像构建器和部署器。在本章中，我们将向您介绍 Google 的 Cloud Code 插件，该插件可在 IntelliJ 等 IDE 中使用。我们将创建一个 Spring Boot 应用程序，并使用 Cloud Code 插件将其部署到本地 Kubernetes 集群。

在本章中，我们将涵盖以下主要主题：

+   介绍 Google 的 Cloud Code 插件

+   安装并使用 IntelliJ Cloud Code 插件

+   创建一个 Spring Boot 应用程序

+   使用 Cloud Code 对 Spring Boot 应用进行容器化和部署

通过本章结束时，您将对 Cloud Code 插件有一个扎实的理解，并了解如何使用它来加速使用 IDE 开发 Kubernetes 应用程序的开发生命周期。

# 技术要求

对于本章，您将需要以下内容：

+   Visual Studio Code ([`code.visualstudio.com/download`](https://code.visualstudio.com/download)) 或 IntelliJ IDE ([`www.jetbrains.com/idea/download/`](https://www.jetbrains.com/idea/download/))

+   Git

+   Spring Boot 2.5

+   OpenJDK 16

本书的 GitHub 存储库中的代码可以在[`github.com/PacktPublishing/Effortless-Cloud-Native-App-Development-Using-Skaffold/tree/main/Chapter07`](https://github.com/PacktPublishing/Effortless-Cloud-Native-App-Development-Using-Skaffold/tree/main/Chapter07)找到。

# 介绍 Google 的 Cloud Code 插件

如果您正在开发或维护当今的云原生应用程序，那么一个不成文的事实是您需要一套工具或工具来简化您的开发过程。作为开发人员，我们通常在内部开发循环中执行以下任务：

+   下载特定的依赖项，如 Skaffold、`minikube`和`kubectl`，以设置本地开发环境。

+   进行大量的上下文切换以查看日志、文档并浏览云供应商提供的控制台。

虽然 Skaffold 是解决这个问题的一个很好的解决方案，但是将所有东西都整合到您的 IDE 中不是很好吗？例如，我们可以添加一个插件来执行所有这些任务并专注于编码部分。为此，我们可以使用 Google Cloud Code 扩展，因为它简化了使用您喜爱的 IDE（如 IntelliJ、Visual Studio Code 等）开发基于云的应用程序。

让我们了解一些 Cloud Code 提供的功能：

+   更快地编写、调试和部署 Kubernetes 应用程序。

+   支持多个 IDE，包括 JetBrains IntelliJ、Visual Studio Code 和 Cloud Shell Editor。

+   多个不同语言的启动模板，以最佳实践快速开始开发。

+   您可以通过单击 Google Kubernetes 引擎或 Cloud Run 来部署您的应用程序。

+   高效地与其他谷歌云平台服务一起使用，包括谷歌 Kubernetes 引擎、谷歌容器注册表和云存储。

+   通过代码片段和内联文档等功能改进 YAML 文件编辑过程。

+   内置对 Skaffold 的支持，加快内部开发循环。

+   轻松远程和本地调试在 Kubernetes 上运行的应用程序。

+   内置日志查看器，实时查看 Kubernetes 应用程序的应用程序日志。

现在我们已经了解了 Cloud Code 是什么以及它的特性，让我们尝试安装和使用其启动模板，快速部署 Java 应用程序到本地 Kubernetes 集群。

# 安装并使用 IntelliJ Cloud Code 插件

要开始使用 Cloud Code 插件，首先我们需要下载它。您可以访问 IntelliJ 插件市场进行下载。让我们学习如何做到这一点：

1.  对于 Windows 或 Linux，导航到**File** | **Settings** | **Plugins**，在搜索区域输入**Cloud Code**，然后单击**Install**。

1.  对于 macOS，导航到**IntelliJ IDEA** | **Preferences** | **Plugins**，在搜索区域输入**Cloud Code**，然后单击**Install**，如下截图所示：![图 7.1 - 从 IntelliJ 市场安装 Cloud Code](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_7.1_B17385.jpg)

图 7.1 - 从 IntelliJ 市场安装 Cloud Code

1.  下载完成后，将弹出一个欢迎屏幕。在这里，单击**创建一个 Kubernetes 示例应用程序**，如下截图所示：![图 7.2 - Cloud Code 欢迎页面](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_7.2_B17385.jpg)

图 7.2 - Cloud Code 欢迎页面

1.  在下一个屏幕上，将打开一个**新项目**窗口。我们需要选择**Java: Guestbook**项目，如下截图所示，然后单击**Next**：![图 7.3 - 选择预构建的 Java Guestbook 应用程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_7.3_B17385.jpg)

图 7.3 - 选择预构建的 Java Guestbook 应用程序

1.  在下一个屏幕上，您将被要求指定您的容器镜像存储库。如果您使用 DockerHub、GCR 或任何其他镜像注册表，则添加这些详细信息，然后单击**下一步**。例如，如果您使用 GCR，则输入类似`gcr.io/gcp-project-id`的内容。由于我们使用启动模板并且镜像名称已在 Kubernetes 清单中定义，因此我们可以留下这部分。

1.  在下一个屏幕上，输入项目名称，然后单击**完成**。示例 Java 项目将下载到默认项目位置。

1.  现在我们有一个可用的项目，单击**运行/调试配置**下拉菜单，然后选择**编辑配置**。

1.  在**运行/调试配置**对话框中，选择**在 Kubernetes 上开发**配置。然后，在**运行** | **部署**下，选择**部署到当前上下文（minikube）**，如下面的屏幕截图所示：![图 7.4 – 将 Kubernetes 的当前上下文设置为 Minikube](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_7.4_B17385.jpg)

图 7.4 – 将 Kubernetes 的当前上下文设置为 Minikube

1.  单击**应用**和**确定**以保存更改。

1.  最后，要在本地 Minikube 集群上运行应用程序，请单击绿色运行图标：![图 7.5 – 运行应用程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_7.5_B17385.jpg)

图 7.5 – 运行应用程序

如前所述，Cloud Code 使用 Skaffold。一旦应用程序成功部署到本地 Minikube 集群，您应该会看到以下输出：

![图 7.6 – 部署日志](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_7.6_B17385.jpg)

图 7.6 – 部署日志

1.  您将在 IntelliJ 的**事件日志**部分收到通知。单击**查看**以访问已部署的 Kubernetes 服务的本地 URL：![图 7.7 – 事件日志通知](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_7.7_B17385.jpg)

图 7.7 – 事件日志通知

1.  您可以单击**java-guestbook-frontend** URL 来访问应用程序：

![图 7.8 – 可用服务](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_7.8_B17385.jpg)

图 7.8 – 可用服务

在访问`http://localhost:4503` URL 后，您应该会看到以下屏幕：

![图 7.9 – 我的留言板应用程序登录页面](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_7.9_B17385.jpg)

图 7.9 – 我的留言板应用程序登录页面

在这一部分，我们安装了 Cloud Code 插件，并使用提供的启动模板快速启动了这个插件。通过我们非常简单的设置，我们构建并部署了一个 Java 应用到本地的 Kubernetes 集群。接下来的部分将创建一个 Spring Boot 应用程序，用于显示实时空气质量数据。

# 创建一个 Spring Boot 应用程序

根据世界卫生组织（https://www.who.int/health-topics/air-pollution）的数据，空气污染每年导致全球约 700 万人死亡。这不仅是发达国家的问题，也是发展中国家的问题。我们应该尽一切努力阻止这种情况发生，采取有力措施。作为技术人员，我们可以创造解决方案，让人们了解他们所在地区的空气质量。有了这个，人们可以采取预防措施，比如在外出时戴口罩，如果室外空气有毒，让老年人和孩子呆在家里。

在这一部分，我们将创建一个 Spring Boot 应用程序，用于显示您当前位置的实时空气质量数据。我们将使用 Openaq（https://openaq.org/）提供的 API，这是一个名为空气质量数据维基百科的非营利组织。它公开了许多实时空气质量数据的端点，但我们将使用[`api.openaq.org/v1/latest?country=IN`](https://api.openaq.org/v1/latest?country=IN) URL 来为我们的 Spring Boot 应用程序。让我们开始吧。

和往常一样，我们将通过浏览[`start.spring.io/`](https://start.spring.io/)来下载一个 Spring Boot 应用程序的工作桩。我们还将为我们的项目添加以下依赖项：

![图 7.10 – Spring Boot 项目 Maven 依赖](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_7.10_B17385.jpg)

图 7.10 – Spring Boot 项目 Maven 依赖

除了我们已经讨论过的依赖项，我们还将添加以下 Dekorate Spring Boot starter 依赖项：

```
<dependency>
    <groupId>io.dekorate</groupId>
    <artifactId>kubernetes-spring-starter</artifactId>
    <version>2.1.4</version>
</dependency>
```

Dekorate（https://github.com/dekorateio/dekorate）是一个工具，可以自动生成 Kubernetes 清单文件。它可以检测应用程序是否具有 Spring Boot web 依赖项，并在编译期间自动生成 Kubernetes 清单文件，并默认配置服务、部署和探针。另外，在你的主类中，你可以添加`@KubernetesApplication`注解来进行一些自定义。例如，你可以提供副本数量、服务类型、入口等等：

```
@KubernetesApplication(serviceType = ServiceType.LoadBalancer, replicas = 2,expose = true)
```

Dekorate 在`target/classes/META-INF/dekorate`目录中以`.json`或`.yml`格式生成 Kubernetes 清单。

以下是 Kubernetes 服务清单的代码：

```
apiVersion: v1
kind: Service
metadata:
  labels:
    app.kubernetes.io/name: scanner
    app.kubernetes.io/version: 0.0.1-SNAPSHOT
  name: scanner
spec:
  ports:
    - name: http
      port: 8080
      targetPort: 8080
  selector:
    app.kubernetes.io/name: scanner
    app.kubernetes.io/version: 0.0.1-SNAPSHOT
  type: LoadBalancer
```

以下是部署 Kubernetes 清单的相关部分。正如您所看到的，Dekorate 已生成了存活和就绪探针：

```
spec:
  containers:
    - env:
        - name: KUBERNETES_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
      image: breathe
      imagePullPolicy: IfNotPresent
      livenessProbe:
        failureThreshold: 3
        httpGet:
          path: /actuator/health/liveness
          port: 8080
          scheme: HTTP
        initialDelaySeconds: 0
        periodSeconds: 30
        successThreshold: 1
        timeoutSeconds: 10
      name: scanner
      ports:
        - containerPort: 8080
          name: http
          protocol: TCP
      readinessProbe:
        failureThreshold: 3
        httpGet:
          path: /actuator/health/readiness
          port: 8080
          scheme: HTTP
        initialDelaySeconds: 0
        periodSeconds: 30
        successThreshold: 1
        timeoutSeconds: 10
```

这是`AirQualityController`类，它已经用`@Controller`注解进行了注释。所有传入的 HTTP 请求到`/index`都由`index()`方法处理，该方法以国家代码、限制、页面和城市名称作为输入。这些参数的默认值分别为`IN`、`5`、`1`和`Delhi`。

根据以下代码片段，我们有一个名为`getAqiForCountry()`的方法，每当我们请求`/index`时都会调用该方法。该方法还使用`RestTemplate`从端点获取实时空气质量数据，如`COUNTRY_AQI_END_POINT`变量中所述，并返回一个`AqiCountryResponse`对象。请参考以下代码：

![图 7.11 - 实时空气质量数据的代码](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_7.11_B17385.jpg)

图 7.11 - 实时空气质量数据的代码

提示

自 5.0 版本以来，`RestTemplate`类已进入维护模式。这意味着只允许进行轻微的错误修复，并且它将在未来被移除，以支持`org.springframework.web.reactive.client.WebClient`类，该类支持同步和异步操作。要使用`WebClient`，您将需要添加另一个依赖，比如`spring-boot-starter-webflux`。如果您想避免只有一个依赖，您也可以使用 Java 11 中新增的新 HTTP 客户端 API。使用这个新 API，我们可以发送同步或异步请求。在下面的同步阻塞示例中，我们使用了`send(HttpRequest, HttpResponse.BodyHandler)`方法。该方法会阻塞，直到请求被发送并收到响应：

`HttpClient httpClient = HttpClient.newBuilder().build();`

`HttpRequest httpRequest = HttpRequest.newBuilder()`

`      .uri(URI.create("URL"))`

`.GET()`

`      .build();`

`HttpResponse<String> syncHttpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());`

同样，对于异步非阻塞，我们可以使用`sendAsync(HttpRequest, HttpResponse.BodyHandler)`方法。它返回一个`CompletableFuture<HttpResponse>`，可以与不同的异步任务结合使用。

`AqiCountryResponse`对象包含以下数据元素：

```
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
  public class AqiCountryResponse {
    public List<Location> results;
}
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
  public class Location {
    public String location;
    public String city;
    public List<Measurement> measurements;
}
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
  public class Measurement {
    public String parameter;
    public String value;
    public String unit;
}
```

最后，我们必须对数据进行排序，并将数据返回到`index.html`页面上，以便在 UI 上呈现。对于 UI 部分，我们使用了 Spring Boot Thymeleaf 依赖。使用以下逻辑，我们可以在`/index.html`页面上显示实时空气质量数据：

```
<div th:if="${ not#lists.isEmpty(response)}">
    <table class="table table-bordered table-striped" 
      id="example" style="width: -moz-max-content">
        <tr>
            <th>Location</th>
            <th>City</th>
            <th colspan="30">Measurements</th>
        </tr>
        <tr th:each="response : ${response}">
            <td th:text="${response.location}"></td>
            <td th:text="${response.city}"></td>
            <th:block th:each="p ${response.measurements}">
                <td th:text="${p.parameter}"></td>
                <td th:text="${p.value}+''+${p.unit}"></td>
            </th:block>
        </tr>
        <table>
</div>
```

我们还创建了一个静态 HTML 表，指定了空气污染级别，并在同一页内为它们分配了颜色。这些颜色使人们可以轻松地确定他们所在地区的污染是否已经达到警戒级别：

```
<table class="table table-bordered" id="example1"
  style="width: max-content">
    <tr>
        <th>AQI</th>
        <th>Air Pollution Level</th>
        <th>Health Implications</th>
        <th>Cautionary Statement (for PM2.5)</th>
    </tr>
    <tr bgcolor="green">
        <td>0-50</td>
        <td>Good</td>
        <td>Air quality is considered satisfactory,
            and air pollution poses little or no risk</td>
        <td>None</td>
    </tr>
    <tr bgcolor="yellow">
        <td>51-100</td>
        <td>Moderate</td>
        <td>Air quality is acceptable; however, 
            for some pollutants there may be a moderate
            health concern for a very small number of
            people who are unusually sensitive to air
            pollution.
        </td>
        <td>Active children and adults, and people with
            respiratory disease, such as asthma,
            should limit prolonged outdoor exertion.
        </td>
    </tr>
<table>
```

此时，应用程序已经准备就绪。我们可以通过使用`mvn sprinboot:run`命令来运行它。让我们这样做，看看我们是否得到了预期的输出。在下面的截图中，您可以看到我们已将默认城市更改为孟买，并且我们可以查看孟买的实时空气质量数据：

![图 7.12 - 呼吸 - 孟买的实时空气质量数据](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_7.12_B17385.jpg)

图 7.12 - 呼吸 - 孟买的实时空气质量数据

在同一页上，我们可以看到一个包含不同 AQI 范围及其严重程度相关信息的表格：

![图 7.13 - 空气质量指数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_7.13_B17385.jpg)

图 7.13 - 空气质量指数

在这一部分，我们创建了一个 Spring Boot 应用程序，用于显示您国家一个城市的实时空气质量数据。

在下一节中，我们将使用 Cloud Code 插件将我们的应用程序容器化并部署到本地的 Kubernetes 集群。

# 使用 Cloud Code 对 Spring Boot 应用程序进行容器化和部署

让我们尝试将我们在上一节中创建的 Spring Boot 应用程序进行容器化和部署。为了容器化我们的 Spring Boot 应用程序，我们将使用`jib-maven-plugin`。我们在之前的章节中多次使用过这个插件，所以我会在这里跳过设置。我们将使用`kubectl`将其部署到本地的 Minikube 集群。让我们学习如何做到这一点：

1.  首先，我们需要在项目的根目录中有一个`skaffold.yaml`文件。

1.  您可以创建一个名为`skaffold.yaml`的空文件，并使用 Cloud Code 的自动补全功能，如下截图所示，生成一个可用的`skaffold.yaml`文件：![图 7.14 - 使用 Cloud Code 创建 skaffold.yaml 文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_7.14_B17385.jpg)

图 7.14 - 使用 Cloud Code 创建 skaffold.yaml 文件

1.  有时，可能会有新的模式版本可用。Cloud Code 足够智能，可以检测到这些更改，并建议您升级模式，如下面的屏幕截图所示：![图 7.15 – 使用 Cloud Code 更新模式版本](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_7.15_B17385.jpg)

图 7.15 – 使用 Cloud Code 更新模式版本

1.  以下是我们的`skaffold.yaml`配置文件的最终版本。在这里，您可以看到我们使用`jib`来将我们的应用程序容器化。我们使用`kubectl`进行部署，我们使用的路径与我们为 Kubernetes 清单生成使用 Dekorate 时使用的路径相同：

```
apiVersion: skaffold/v2beta20
kind: Config
metadata:
  name: scanner
build:
  artifacts:
  - image: breathe
    jib:
      project: com.air.quality:scanner
deploy:
  kubectl:
    manifests:
      - target/classes/META-INF/dekorate/kubernetes.yml
```

在创建`skaffold.yaml`配置文件后不久，Cloud Code 检测到更改，并建议我们**创建 Cloud Code Kubernetes 运行配置**，如下所示：

![图 7.16 – 使用 Cloud Code 创建运行配置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_7.16_B17385.jpg)

图 7.16 – 使用 Cloud Code 创建运行配置

1.  单击此选项后，在 IntelliJ 的**运行/调试**配置下，将创建两个名为**在 Kubernetes 上开发**和**在 Kubernetes 上运行**的新配置文件：![图 7.17 – Cloud Code 配置文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_7.17_B17385.jpg)

图 7.17 – Cloud Code 配置文件

1.  要在持续开发模式下运行我们的应用程序，请从下拉菜单中选择**在 Kubernetes 上开发**。Cloud Code 在此模式下内部使用`skaffold dev`命令。它将为您执行以下操作：

+   它将开始监视源代码的更改。

+   它将使用 Jib 对我们的 Spring Boot 应用程序进行容器化。由于我们使用的是本地 Kubernetes 集群，Skaffold 足够智能，不会将图像推送到远程注册表以实现快速内部开发循环。相反，它将图像加载到本地 Docker 守护程序中。

+   它将部署图像到 Minikube 集群，端口转发到端口`8080`，并在您的 IDE 中开始流式传输日志。您的 IDE 中的事件日志将显示服务 URL，您可以使用该 URL 访问您的应用程序。输出将类似于我们在上一节中看到的内容。

**在 Kubernetes 上运行**选项类似于`skaffold run`命令。您可以使用此选项在需要时部署，而不是在每次代码更改时都这样做。

即使我们还没有这样做，您甚至可以使用 Cloud Code 部署到远程 Kubernetes 集群。如果您的 Kubernetes 上下文指向像 GKE 这样的远程集群，那么 Cloud Code 也可以在那里进行部署。如果您没有远程集群，Cloud Code 也可以帮助您创建。

Cloud Code 具有良好的集成，可以运行无服务器工作负载，以及使用谷歌的 Cloud Run。

在本节中，您学习了如何使用 Cloud Code 将 Spring Boot 应用程序容器化并部署到本地 Kubernetes 集群。现在，让我们总结一下本章。

# 总结

在本章中，您学习了如何使用谷歌开发的 Cloud Code 插件，从您的 IDE 中进行单击部署 Kubernetes 应用程序。我们从解释 Cloud Code 的各种功能开始了本章。在示例中，我们解释了如何使用 Cloud Code 提供的启动模板从您的 IDE 中编写、构建和部署 Java 应用程序。然后，我们创建了一个使用 Dekorate 在编译时生成 Kubernetes 清单的 Spring Boot 应用程序。最后，我们将 Spring Boot 应用程序容器化并部署到本地 Minikube 集群。

通过这样做，您已经发现了如何使用 Cloud Code 在开发云原生应用程序时提高生产力。

下一章将讨论如何将 Spring Boot 应用程序部署到 Google Kubernetes Engine。


# 第八章：使用 Skaffold 将 Spring Boot 应用部署到 Google Kubernetes Engine

在上一章中，您学习了如何使用 Google 的 IntelliJ 的 Cloud Code 插件将 Spring Boot 应用部署到本地 Kubernetes 集群。本章重点介绍了如何将相同的 Spring Boot 应用部署到远程 Google Kubernetes Engine（GKE），这是 Google Cloud Platform（GCP）提供的托管 Kubernetes 服务。我们还将向您介绍 Google 最近推出的无服务器 Kubernetes 服务 GKE Autopilot。您还将了解 Google Cloud SDK 和 Cloud Shell，并使用它们来连接和管理远程 Kubernetes 集群。

在本章中，我们将涵盖以下主要主题：

+   开始使用 Google Cloud Platform

+   使用 Google Cloud SDK 和 Cloud Shell

+   设置 Google Kubernetes Engine

+   介绍 GKE Autopilot 集群

+   将 Spring Boot 应用部署到 GKE

到本章结束时，您将对 GCP 提供的基本服务有深入的了解，以便将 Spring Boot 应用部署到 Kubernetes。

# 技术要求

您需要在系统上安装以下内容才能按照本章的示例进行操作：

+   Eclipse ([`www.eclipse.org/downloads/`](https://www.eclipse.org/downloads/)) 或 IntelliJ IDE ([`www.jetbrains.com/idea/download/`](https://www.jetbrains.com/idea/download/))

+   Git ([`git-scm.com/downloads`](https://git-scm.com/downloads))

+   Google Cloud SDK

+   GCP 账户

+   Spring Boot 2.5

+   OpenJDK 16

本章中的代码示例也可以在 GitHub 上找到：[`github.com/PacktPublishing/Effortless-Cloud-Native-App-Development-Using-Skaffold`](https://github.com/PacktPublishing/Effortless-Cloud-Native-App-Development-Using-Skaffold)。

# 开始使用 Google Cloud Platform

今天，许多组织利用不同云提供商提供的服务，如亚马逊网络服务（AWS）、谷歌的 GCP、微软 Azure、IBM 云或甲骨文云。使用这些云供应商的优势在于您无需自行管理基础架构，通常按小时支付这些服务器的使用费用。此外，大多数情况下，如果组织不了解或未能解决其应用程序所需的计算能力，可能会导致计算资源的过度配置。

如果您自行管理基础架构，就必须雇佣一大批人员来负责维护活动，如打补丁操作系统、升级软件和升级硬件。这些云供应商通过为我们提供这些服务来帮助我们解决业务问题。此外，这些云供应商支持的产品都具有内置的维护功能，无论是数据库还是 Kubernetes 等托管服务。如果您已经使用过这些云供应商中的任何一个，您可能会发现所有这些供应商提供类似的服务或产品，但实施和工作方式是不同的。

例如，您可以在链接[`cloud.google.com/free/docs/aws-azure-gcp-service-comparison`](https://cloud.google.com/free/docs/aws-azure-gcp-service-comparison)中查看 GCP 提供的服务及其 AWS 和 Azure 等价物。

现在我们知道使用这些云供应商有不同用例的优势，让我们谈谈一个这样的云供应商——谷歌云平台。

谷歌云平台（通常缩写为 GCP）为您提供一系列服务，如按需虚拟机（通过谷歌计算引擎）、用于存储文件的对象存储（通过谷歌云存储）和托管的 Kubernetes（通过谷歌 Kubernetes 引擎）等。

在开始使用谷歌的云服务之前，您首先需要注册一个帐户。如果您已经拥有谷歌帐户，如 Gmail 帐户，那么您可以使用该帐户登录，但您仍需要单独注册云帐户。如果您已经在谷歌云平台上注册，可以跳过此步骤。

首先，转到[`cloud.google.com`](https://cloud.google.com)。接下来，您将被要求进行典型的 Google 登录流程。如果您还没有 Google 帐户，请按照注册流程创建一个。以下屏幕截图是 Google Cloud 登录页面：

![图 8.1 - 开始使用 Google Cloud](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.1_B17385.jpg)

图 8.1 - 开始使用 Google Cloud

如果您仔细查看屏幕截图，会发现它说**新客户可获得价值 300 美元的 Google Cloud 免费信用额度。所有客户都可以免费使用 20 多种产品**。这意味着您可以免费使用免费套餐产品，而无需支付任何费用，并且您还将获得价值 300 美元的信用额度，可供您在 90 天内探索或评估 GCP 提供的不同服务。例如，您可以在指定的月度使用限制内免费使用 Compute Engine、Cloud Storage 和**BigQuery**。

您可以单击**免费开始**或**登录**。如果您是第一次注册，必须提供您的计费信息，这将重定向您到您的云**控制台**。此外，系统会自动为您创建一个新项目。项目是您的工作空间。单个项目中的所有资源都与其他项目中的资源隔离。您可以控制对该项目的访问，并仅授予特定个人或服务帐户访问权限。以下屏幕截图是您的 Google Cloud 控制台仪表板视图：

![图 8.2 - Google Cloud 控制台仪表板](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.2_B17385.jpg)

图 8.2 - Google Cloud 控制台仪表板

在控制台页面的左侧，您可以查看 GCP 提供的不同服务：

![图 8.3 - Google Cloud 服务视图](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.3_B17385.jpg)

图 8.3 - Google Cloud 服务视图

在本章中，重点将放在 GCP 提供的 GKE 服务 API 上。但在讨论这些服务之前，我们需要安装一些工具来使用这些服务。让我们在下一节讨论这些工具。

# 使用 Google Cloud SDK 和 Cloud Shell

您现在可以访问 GCP 控制台，并且可以使用控制台几乎可以做任何事情。但是，开发人员的更好方法是使用 Cloud SDK，这是一组工具，允许通过使用仿真器或**kubectl**、**Skaffold**和**minikube**等工具进行更快的本地开发。不仅如此，您还可以管理资源，对远程 Kubernetes 集群进行身份验证，并从本地工作站启用或禁用 GCP 服务。另一个选项是从浏览器使用 Cloud Shell，我们将在本章中探索这两个选项。Cloud SDK 为您提供了与其产品和服务进行交互的工具和库。在使用 Cloud SDK 时，您可以根据需要安装和删除组件。

让我们从 Cloud SDK 开始。您可以转到[`cloud.google.com/sdk/`](https://cloud.google.com/sdk/)并单击**开始**按钮。这将重定向您到安装指南。Cloud SDK 的最低先决条件是具有 Python。支持的版本包括 Python 3（首选 3.5 到 3.8）和 Python 2（2.7.9 或更高版本）。例如，现代版本的 macOS 包括 Cloud SDK 所需的适当版本的 Python。但是，如果您想要安装带有 Cloud SDK 的 Python 3，可以选择带有捆绑 Python 安装的 macOS 64 位版本。

## 在 Linux 上下载 Cloud SDK

Cloud SDK 需要安装 Python，因此首先使用以下命令验证 Python 版本：

```
python --version
```

要从命令行下载 Linux 64 位存档文件，请运行以下命令：

```
curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-336.0.0-linux-x86_64.tar.gz
```

对于 32 位存档文件，请运行以下命令：

```
curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-336.0.0-linux-x86.tar.gz
```

## 在 macOS 上下载 Cloud SDK

要在 macOS 上下载 Cloud SDK，您可以选择以下选项：

![图 8.4 - macOS 的下载选项](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.4_B17385.jpg)

图 8.4 - macOS 的下载选项

如果您不确定您的机器硬件，那么运行`uname -m`命令。根据您的机器，您将获得以下输出：

```
$uname -m
x86_64
```

现在选择适当的软件包，并从[`cloud.google.com/sdk/docs/install#mac`](https://cloud.google.com/sdk/docs/install#mac)中的表中的**软件包**列中给出的 URL 进行下载。

## 设置 Cloud SDK

下载软件包后，您需要将存档提取到文件系统上您选择的位置。以下是提取的`google-cloud-sdk`存档的内容：

```
tree -L 1 google-cloud-sdk
google-cloud-sdk
├── LICENSE
├── README
├── RELEASE_NOTES
├── VERSION
├── bin
├── completion.bash.inc
├── completion.zsh.inc
├── data
├── deb
├── install.bat
├── install.sh
├── lib
├── path.bash.inc
├── path.fish.inc
├── path.zsh.inc
├── platform
├── properties
└── rpm
```

解压缩存档后，您可以通过运行存档根目录中的`install.sh`脚本来继续安装。您可能会看到以下输出：

```
$ ./google-cloud-sdk/install.sh 
Welcome to the Google Cloud SDK!
To help improve the quality of this product, we collect anonymized usage data
and anonymized stacktraces when crashes are encountered; additional information
is available at <https://cloud.google.com/sdk/usage-statistics>. This data is
handled in accordance with our privacy policy
<https://cloud.google.com/terms/cloud-privacy-notice>. You may choose to opt in this
collection now (by choosing 'Y' at the below prompt), or at any time in the
future by running the following command:
    gcloud config set disable_usage_reporting false
Do you want to help improve the Google Cloud SDK (y/N)?  N
Your current Cloud SDK version is: 336.0.0
The latest available version is: 336.0.0
```

在以下屏幕中，您可以看到已安装和未安装的组件列表：

![图 8.5 – Google Cloud SDK 组件列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.5_B17385.jpg)

图 8.5 – Google Cloud SDK 组件列表

您可以使用以下 Cloud SDK 命令来安装或移除组件：

```
To install or remove components at your current SDK version [336.0.0], run:
  $ gcloud components install COMPONENT_ID
  $ gcloud components remove COMPONENT_ID
Enter a path to an rc file to update, or leave blank to use 
[/Users/ashish/.zshrc]:  
No changes necessary for [/Users/ashish/.zshrc].
For more information on how to get started, please visit:
  https://cloud.google.com/sdk/docs/quickstarts
```

确保在此之后使用`source .zshrc`命令来源化您的 bash 配置文件。从安装中，您可以看到默认只安装了三个组件，即`. bq`、`core`和`gsutil`。

下一步是运行`gcloud init`命令来初始化 SDK，使用以下命令：

```
$/google-cloud-sdk/bin/gcloud init  
Welcome! This command will take you through the configuration of gcloud.
Your current configuration has been set to: [default]
You can skip diagnostics next time by using the following flag:
  gcloud init --skip-diagnostics
Network diagnostic detects and fixes local network connection issues.
Checking network connection...done
Reachability Check passed.
Network diagnostic passed (1/1 checks passed).
You must log in to continue. Would you like to log in (Y/n)?  Y
Your browser has been opened to visit:
    https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=32555940559.apps.googleusercontent.com&redirect_uri=http%3A%2F%2Flocalhost%3A8085%2F&scope=openid+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email+https%3A%2F%2Flocalhost%3A8085%2F&scope=openid+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fappengine.admin+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcompute+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Faccounts.reauth&state=CU1Yhij0NWZB8kZvNx6aAslkkXdlYf&access_type=offline&code_challenge=sJ0_hf6-zNKLjVSw9fZlxjLodFA-EsunnBWiRB5snmw&code_challenge_method=S256
```

此时，您将被重定向到浏览器窗口，并被要求登录您的 Google 账户进行身份验证，并授予 Cloud SDK 对您的云资源的访问权限。

点击**允许**按钮，确保下次可以作为自己与 GCP API 进行交互。授予访问权限后，您将看到以下屏幕以确认身份验证：

![图 8.6 – Google Cloud SDK 身份验证完成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.6_B17385.jpg)

图 8.6 – Google Cloud SDK 身份验证完成

现在您已经完成了身份验证，并准备好使用 Cloud SDK 进行工作。完成身份验证后，您可能会在命令行上看到以下内容：

```
Updates are available for some Cloud SDK components.  To install them,
please run:
  $ gcloud components update
You are logged in as: [XXXXXXX@gmail.com].
Pick cloud project to use: 
 [1] xxxx-xxx-307204
 [2] Create a new project
Please enter numeric choice or text value (must exactly match list 
item):  1
Your current project has been set to: [your-project-id].
Do you want to configure a default Compute Region and Zone? (Y/n)?  Y
Which Google Compute Engine zone would you like to use as project 
default?
If you do not specify a zone via a command line flag while working 
with Compute Engine resources, the default is assumed.
 [1] us-east1-b
 [2] us-east1-c
 [3] us-east1-d
.................
Please enter a value between 1 and 77, or a value present in the list:  1
Your project default Compute Engine zone has been set to [us-east1-b].
You can change it by running [gcloud config set compute/zone NAME].
Your project default Compute Engine region has been set to [us-east1].
You can change it by running [gcloud config set compute/region NAME].
Your Google Cloud SDK is configured and ready to use!
......
```

从命令行输出可以清楚地看出，我们已经选择了项目并确认了计算引擎区域。现在，我们已经成功安装了 Cloud SDK。在下一节中，我们将学习有关 Cloud Shell 的内容。

### 使用 Cloud Shell

Cloud Shell 是一个基于浏览器的终端/CLI 和编辑器。它预装了诸如 Skaffold、minikube 和 Docker 等工具。您可以通过单击 Cloud 控制台浏览器窗口右上角的以下图标来激活它：

![图 8.7 – 激活 Cloud Shell](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.7_B17385.jpg)

图 8.7 – 激活 Cloud Shell

激活后，您将被重定向到以下屏幕：

![图 8.8 – Cloud Shell 编辑器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.8_B17385.jpg)

图 8.8 – Cloud Shell 编辑器

您可以使用`gcloud config set project projectid`命令设置您的项目 ID，或者只是开始使用`gcloud`命令进行操作。以下是 Cloud Shell 提供的一些突出功能：

+   Cloud Shell 完全基于浏览器，并且您可以从任何地方访问它。唯一的要求是互联网连接。

+   Cloud Shell 为您的`$HOME`目录挂载了 5GB 的持久存储。

+   Cloud Shell 带有在线代码编辑器。您可以使用它来构建、测试和调试您的应用程序。

+   Cloud Shell 还带有安装的 Git 客户端，因此您可以从代码编辑器或命令行克隆和推送更改到您的存储库。

+   Cloud Shell 带有 Web 预览，您可以在 Web 应用中查看本地更改。

我们已经为我们的使用安装和配置了 Google Cloud SDK。我们还看了 Cloud Shell 及其提供的功能。现在让我们创建一个 Kubernetes 集群，我们可以在其中部署我们的 Spring Boot 应用程序。

# 设置 Google Kubernetes Engine 集群

我们需要在 GCP 上设置一个 Kubernetes 集群，以部署我们的容器化 Spring Boot 应用程序。GCP 可以提供托管和管理的 Kubernetes 部署。我们可以使用以下两种方法在 GCP 上创建 Kubernetes 集群：

+   使用 Google Cloud SDK 创建 Kubernetes 集群

+   使用 Google 控制台创建 Kubernetes 集群

让我们详细讨论每个。 

## 使用 Google Cloud SDK 创建 Kubernetes 集群

我们可以使用以下 gcloud SDK 命令创建用于运行容器的 Kubernetes 集群。这将使用默认设置创建一个 Kubernetes 集群：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.9_B17385.jpg)

图 8.9 - GKE 集群已启动

我们已成功使用 Cloud SDK 创建了一个 Kubernetes 集群。接下来，我们将尝试使用 Google 控制台创建集群。

## 使用 Google 控制台创建 Kubernetes 集群

要使用控制台创建 Kubernetes 集群，您应首先使用左侧导航栏并选择**Kubernetes Engine**。在呈现的选项中，选择**Clusters**：

![图 8.10 - 开始使用 Google Kubernetes Engine 创建集群](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.10_B17385.jpg)

图 8.10 - 开始使用 Google Kubernetes Engine 创建集群

之后，您将在下一页上看到以下屏幕：

![图 8.11 - 创建 Google Kubernetes Engine 集群](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.11_B17385.jpg)

图 8.11 - 创建 Google Kubernetes Engine 集群

您可以通过单击弹出窗口上的**CREATE**按钮或单击页面顶部的**+CREATE**来选择创建集群。两者都会为您提供以下选项可供选择，如*图 8.12*中所述：

![图 8.12 – Google Kubernetes Engine 集群模式](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.12_B17385.jpg)

图 8.12 – Google Kubernetes Engine 集群模式

您可以选择创建**标准**Kubernetes 集群，或者选择完全无需操作的**Autopilot**模式。在本节中，我们将讨论标准集群。我们将在下一节单独讨论 Autopilot。

在标准集群模式下，您可以灵活选择集群节点的数量，并根据需要调整配置或设置。以下是创建 Kubernetes 集群的步骤。由于我们使用默认配置，您必须单击**下一步**接受默认选项。

![图 8.13 – Google Kubernetes Engine 集群创建](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.13_B17385.jpg)

图 8.13 – Google Kubernetes Engine 集群创建

最后，单击页面底部的**创建**按钮，您的 Kubernetes 集群将在几分钟内运行起来！

以下是您集群的默认配置：

![图 8.14 – Google Kubernetes Engine 集群配置视图](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.14_B17385.jpg)

图 8.14 – Google Kubernetes Engine 集群配置视图

您的 Kubernetes 集群现在已经运行起来。在下面的截图中，我们可以看到我们有一个三节点集群，具有六个 vCPU 和 12GB 的总内存：

![图 8.15 – Google Kubernetes Engine 集群已经运行](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.15_B17385.jpg)

图 8.15 – Google Kubernetes Engine 集群已经运行

您可以通过单击集群名称**cluster-1**查看有关集群节点、存储和日志的更多详细信息。以下是我们刚刚创建的集群节点的详细信息：

![图 8.16 – Google Kubernetes Engine 集群视图](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.16_B17385.jpg)

图 8.16 – Google Kubernetes Engine 集群视图

您可以看到整体集群状态和节点健康状况都是正常的。集群节点是使用 Compute Engine GCP 创建的，并提供机器类型为**e2-medium**。您可以通过查看左侧导航栏上的 Compute Engine 资源来验证这一点。我们在这里显示了相同的三个节点，GKE 集群使用了我们刚刚创建的这些节点。

![图 8.17 – Google Kubernetes Engine 集群 VM 实例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.17_B17385.jpg)

图 8.17 – Google Kubernetes Engine 集群 VM 实例

我们已经学会了如何使用 Google 控制台创建一个 Kubernetes 标准集群。在接下来的部分，我们将学习关于 Autopilot 集群。

# 介绍 Google Kubernetes Engine Autopilot 集群

2021 年 2 月 24 日，Google 宣布了他们完全托管的 Kubernetes 服务 GKE Autopilot 的一般可用性。这是一个完全托管和无服务器的 Kubernetes 即服务提供。目前没有其他云提供商在管理云上的 Kubernetes 集群时提供这种级别的自动化。大多数云提供商会让你自己管理一些集群管理工作，无论是管理控制平面（API 服务器、etcd、调度器等）、工作节点，还是根据你的需求从头开始创建一切。

正如其名字所示，GKE Autopilot 是一个完全无需干预的体验，在大多数情况下，你只需要指定一个集群名称和区域，如果需要的话设置网络，就这样。你可以专注于部署你的工作负载，让 Google 完全管理你的 Kubernetes 集群。Google 为 Autopilot pods 在多个区域提供 99.9%的正常运行时间。即使你自己管理这些，也无法达到 Google 提供的数字。此外，GKE Autopilot 是具有成本效益的，因为你不需要支付虚拟机（VMs）的费用，你只需要按资源的秒数计费（例如，被你的 pods 消耗的 vCPU、内存和磁盘空间）。

那么，我们在上一节中创建的 GKE 标准集群和 GKE Autopilot 集群有什么区别呢？答案如下：对于标准集群，你只管理节点，因为 GKE 管理控制平面；而对于 GKE Autopilot，你什么都不用管理（甚至不用管理你的工作节点）。

这引发了一个问题：我无法控制我的节点是好事还是坏事？现在，这是值得讨论的，但是今天大多数组织并不像 amazon.com、google.com 或 netflix.com 那样处理流量或负载。这可能是一个过于简化的说法，但老实说，即使您认为自己有特定的需求或需要一个专门的集群，往往最终会浪费大量时间和资源来保护和管理您的集群。如果您有一支 SRE 团队，他们可以匹敌 Google SRE 的经验或知识水平，您可以随心所欲地处理您的集群。但是今天大多数组织并没有这样的专业知识，也不知道他们在做什么。这就是为什么最好依赖完全托管的 Kubernetes 服务，比如 GKE Autopilot – 它经过了实战测试，并且根据从 Google SRE 学到的最佳实践进行了加固。

我们已经讨论了足够多关于 GKE 自动驾驶的特性以及它提供的完全抽象，然而，要记住这些抽象，也有一些限制。例如，在自动驾驶模式下，您不能为容器运行特权模式。有关限制的完整列表，请阅读官方文档：[`cloud.google.com/kubernetes-engine/docs/concepts/autopilot-overview#limits`](https://cloud.google.com/kubernetes-engine/docs/concepts/autopilot-overview#limits)。

到目前为止，我们已经对 GKE 自动驾驶有了足够的了解，现在是时候创建我们的集群了。让我们开始吧！

## 创建自动驾驶集群

在单击**配置**按钮之后，如*图 8.13*中所述，您将被重定向到以下屏幕：

![图 8.18 – 创建 GKE 自动驾驶集群](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.18_B17385.jpg)

图 8.18 – 创建 GKE 自动驾驶集群

自动驾驶集群具有节点管理、网络、安全和遥测等功能，这些功能已经内置了 Google 推荐的最佳实践。GKE 自动驾驶确保您的集群经过了优化，并且已经准备好投入生产。

正如您所见，您在这里可以更改的选项非常少。您可以更改集群的**名称**，选择另一个**区域**，或选择**网络**（即公共或私有）。在**网络选项**下，您可以更改诸如网络、子网络、Pod IP 地址范围和集群服务 IP 地址范围等内容，如下面的屏幕截图所示：

![图 8.19 – GKE 自动驾驶集群配置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.19_B17385.jpg)

图 8.19 – GKE Autopilot 集群配置

在**高级选项**下，您可以启用维护窗口，并允许特定时间范围内的维护排除（如*图 8.19*所示）。在此窗口中，您的 GKE 集群将进行自动维护窗口，并且不会对您可用。您应根据自己的需求选择维护窗口。

![图 8.20 – 配置 GKE Autopilot 集群维护窗口](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.20_B17385.jpg)

图 8.20 – 配置 GKE Autopilot 集群维护窗口

现在，我们将使用默认值并单击页面底部的**创建**按钮来创建集群。创建集群可能需要几分钟时间。在下面的屏幕截图中，您可以看到 Autopilot 集群已经运行：

![图 8.21 – GKE Autopilot 集群已经运行](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.21_B17385.jpg)

图 8.21 – GKE Autopilot 集群已经运行

在这里，您可以看到节点的数量没有被提及，因为它是由 GKE 管理的。

接下来，我们可以尝试连接到这个集群。要这样做，请单击屏幕右上角的三个点，然后单击**连接**：

![图 8.22 – 连接到 GKE Autopilot 集群](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.22_B17385.jpg)

图 8.22 – 连接到 GKE Autopilot 集群

单击**连接**后，应该会出现以下弹出窗口。您可以将此处提到的命令复制到您的 CLI 或 Cloud Shell 中：

![图 8.23 – 连接到 GKE Autopilot 集群的命令](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.23_B17385.jpg)

图 8.23 – 连接到 GKE Autopilot 集群的命令

然后，您可以使用以下`kubectl get nodes`命令验证集群详细信息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.24_B17385.jpg)

图 8.24 – kubectl 命令输出

我们还可以使用以下命令在自动驾驶模式下创建 GKE 集群：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.25_B17385.jpg)

图 8.25 – 自动驾驶模式下的 GKE 集群

我们也可以在 Google Cloud 控制台上进一步验证。您可以看到我们现在有两个集群。第一个是使用 Cloud 控制台创建的，第二个是使用 gcloud 命令行创建的。

![图 8.26 – GKE Autopilot 和标准模式集群](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.26_B17385.jpg)

图 8.26 – GKE Autopilot 集群

我们已经了解了在 GCP 上创建 Kubernetes 集群的不同方式。现在，让我们使用 Skaffold 将一个可工作的 Spring Boot 应用程序部署到 GKE。

# 将 Spring Boot 应用程序部署到 GKE

我们将在本节中使用的 Spring Boot 应用程序与上一章中相同（我们命名为*Breathe – View Real-Time Air Quality Data*的应用程序）。我们已经熟悉这个应用程序，所以我们将直接跳转到部署到 GKE。我们将使用在上一节中创建的`gke-autopilot-cluster1`来进行部署。我们将使用 Skaffold 使用以下两种方法进行部署：

+   使用 Skaffold 从本地部署到远程 GKE 集群

+   使用 Skaffold 从 Cloud Shell 部署到 GKE 集群

## 使用 Skaffold 从本地部署到远程 GKE 集群

在本节中，您将学习如何使用 Skaffold 将 Spring Boot 应用程序部署到远程 Kubernetes 集群。让我们开始吧：

1.  在上一章中，我们使用**Dockerfile**将我们的 Spring Boot 应用程序容器化。然而，在本章中，我们将使用`Jib-Maven`插件来容器化应用程序。我们已经知道如何在以前的章节中使用 jib-maven 插件，所以我们将跳过在这里再次解释这个。

1.  唯一的变化是我们将使用**Google 容器注册表**（**GCR**）来存储 Jib 推送的图像。GCR 是您图像的安全私有注册表。在那之前，我们需要确保 GCR 访问已对您的帐户启用。您可以使用以下`gcloud`命令来允许访问：

```
gcloud services enable containerregistry.googleapis.com
```

或者您可以转到[`cloud.google.com/container-registry/docs/quickstart`](https://cloud.google.com/container-registry/docs/quickstart)，并通过单击**启用 API**按钮来启用容器注册表 API。

![图 8.27 – 启用 Google 容器注册表 API](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.27_B17385.jpg)

图 8.27 – 启用 Google 容器注册表 API

接下来，您将被要求选择一个项目，然后单击**继续**。就是这样！

![图 8.28 – 为容器注册表 API 注册您的应用程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.28_B17385.jpg)

图 8.28 – 为容器注册表 API 注册您的应用程序

1.  您还可以使容器注册表中的图像对公共访问可用。如果它们是公共的，您的图像用户可以在不进行任何身份验证的情况下拉取图像。在下面的屏幕截图中，您可以看到一个选项，**启用漏洞扫描**，用于推送到您的容器注册表的图像。如果您愿意，您可以允许它扫描您的容器图像以查找漏洞。![图 8.29 – GCR 设置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.29_B17385.jpg)

图 8.29 – GCR 设置

1.  下一个谜题的部分是创建 Kubernetes 清单，如**Deployment**和**Service**。在上一章中，我们使用了**Dekorate**工具（[`github.com/dekorateio/dekorate`](https://github.com/dekorateio/dekorate)）创建了它们。在这里，我们将继续使用相同的 Kubernetes 清单生成过程。生成的 Kubernetes 清单位于`target/classes/META-INF/dekorate/kubernetes.yml`路径下。

1.  接下来，我们将运行`skaffold init --XXenableJibInit`命令，这将为我们创建一个`skaffold.yaml`配置文件。您可以看到 Skaffold 在生成的`skaffold.yaml`文件的`deploy`部分中添加了 Kubernetes 清单的路径，并将使用`jib`进行镜像构建：

```
apiVersion: skaffold/v2beta20
kind: Config
metadata:
  name: scanner
build:
artifacts:
  - image: breathe
    jib:
      project: com.air.quality:scanner
deploy:
  kubectl:
    manifests:
    - target/classes/META-INF/dekorate/kubernetes.yml
```

1.  我们有与上一章中解释的相同的主类，该主类使用了 Dekorate 工具提供的`@KubernetesApplication` `(serviceType = ServiceType.LoadBalancer)`注解，将服务类型声明为`LoadBalancer`：

```
@KubernetesApplication(serviceType = ServiceType.LoadBalancer)
@SpringBootApplication
public class AirQualityScannerApplication {
   public static void main(String[] args) {
      SpringApplication.run(AirQualityScannerApplication.        class, args);
   }
}
```

在编译时，Dekorate 将生成以下 Kubernetes 清单。我还将它们保存在源代码的 k8s 目录中，因为有时我们必须手动添加或删除 Kubernetes 清单中的内容。部署和服务 Kubernetes 清单也可以在 GitHub 上找到：[`github.com/PacktPublishing/Effortless-Cloud-Native-App-Development-Using-Skaffold/blob/main/Chapter07/k8s/kubernetes.yml`](https://github.com/PacktPublishing/Effortless-Cloud-Native-App-Development-Using-Skaffold/blob/main/Chapter07/k8s/kubernetes.yml)。

接下来，我们需要确保您已经通过`gcloud auth list`命令进行了身份验证，以便使用 Google Cloud 服务。您将看到以下输出：

```
Credentialed AccountsACTIVE  ACCOUNT*       <my_account>@<my_domain.com>To set the active account, run:    $ gcloud config set account 'ACCOUNT'
```

如果您尚未进行身份验证，也可以使用`gcloud auth login`命令。

1.  如果尚未设置，请使用`gcloud config set project <PROJECT_ID>`命令设置您的 GCP 项目。

1.  确保 Kubernetes 上下文设置为远程 Google Kubernetes 集群。使用以下命令进行验证：

```
$ kubectl config current-context    
gke_project_id_us-east1_gke-autopilot-cluster1
```

1.  现在我们已经准备好部署。让我们运行`skaffold run --default-repo=gcr.io/<PROJECT_ID>`命令。这将构建应用程序的容器镜像，并将其推送到远程 GCR。![图 8.30 – 镜像推送到 Google 容器注册表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.30_B17385.jpg)

图 8.30 – 镜像推送到 Google 容器注册表

推送的镜像详细信息可以在以下截图中看到：

![图 8.31 – Google 容器注册表图像视图](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.31_B17385.jpg)

图 8.31 – Google 容器注册表图像视图

1.  最后，将其部署到远程 Google Kubernetes 集群。第一次运行时，部署需要一些时间来稳定，但后续运行会快得多。![图 8.32 – Skaffold 运行输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.32_B17385.jpg)

图 8.32 – Skaffold 运行输出

1.  我们还可以在 Google Cloud 控制台上查看部署状态。转到**Kubernetes Engine**，然后单击左侧导航栏上的**工作负载**选项卡以查看部署状态。部署状态为**OK**。![图 8.33 – 部署状态](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.33_B17385.jpg)

图 8.33 – 部署状态

您可以通过单击应用程序名称查看更多**部署**详情。

![图 8.34 – 部署详情](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.34_B17385.jpg)

图 8.34 – 部署详情

1.  到目前为止一切看起来都很好。现在我们只需要服务的 IP 地址，这样我们就可以访问我们的应用程序了。在同一部署详情页面的底部，我们有关于我们的服务的详细信息。![图 8.35 – 暴露的服务](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.35_B17385.jpg)

图 8.35 – 暴露的服务

1.  让我们访问 URL 并验证是否获得了期望的输出。我们可以查看德里的实时空气质量数据：![图 8.36 – Spring Boot 应用响应](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.36_B17385.jpg)

图 8.36 – Spring Boot 应用响应

1.  我们可以使用执行器`/health/liveness`和`/health/readiness`端点来验证应用程序的健康状况。我们已经将这些端点用作部署到 Kubernetes 集群的 Pod 的活跃性和就绪性探针。

![图 8.37 – Spring Boot 应用执行器探针](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.37_B17385.jpg)

图 8.37 – Spring Boot 应用执行器探针

通过这些步骤，我们已经完成了使用 Skaffold 从本地工作站将我们的 Spring Boot 应用部署到远程 Google Kubernetes 集群。在下一节中，我们将学习如何从基于浏览器的 Cloud Shell 环境部署应用到 GKE。

## 使用 Skaffold 从 Cloud Shell 部署到 GKE 集群

在本节中，重点将放在使用基于浏览器的 Cloud Shell 工具将 Spring Boot 应用部署到 GKE 上。让我们开始吧！

1.  第一步是激活 Cloud Shell 环境。这可以通过在 Google Cloud 控制台右上角点击**激活 Cloud Shell**图标来完成。![图 8.38 – Cloud Shell 编辑器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.38_B17385.jpg)

图 8.38 – Cloud Shell 编辑器

1.  如前一个截图所示，您被要求使用`gcloud config set project [PROJECT_ID]`命令设置您的 Cloud `PROJECT_ID`。如果您知道您的`PROJECT_ID`，您可以使用这个命令，或者使用`gcloud projects list`等命令。之后，Cloud Shell 将请求授权您的请求，通过调用 GCP API。之后，您无需为每个请求提供凭据。![图 8.39 – 授权 Cloud Shell](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.39_B17385.jpg)

图 8.39 – 授权 Cloud Shell

我们需要在 Cloud Shell 环境中的应用程序源代码。Cloud Shell 带有安装了 Git 客户端，因此我们可以运行`git clone` [`github.com/PacktPublishing/Effortless-Cloud-Native-App-Development-using-Skaffold.git`](https://github.com/PacktPublishing/Effortless-Cloud-Native-App-Development-using-Skaffold.git)命令并克隆我们的 GitHub 存储库。

![图 8.40 – 克隆 GitHub 存储库](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.40_B17385.jpg)

图 8.40 – 克隆 GitHub 存储库

1.  接下来，您需要编译项目，以便生成 Kubernetes 清单。运行`./mvnw clean compile`命令来构建您的项目。您的构建将失败，并且您将收到错误：

```
[ERROR] Failed to execute goal org.apache.maven.plugins:maven-compiler-plugin:3.8.1:compile (default-compile) on project scanner: Fatal error compiling: error: invalid target release: 16 -> [Help 1] . 
```

失败的原因是在 Cloud Shell 环境中将`JAVA_HOME`设置为 Java 11：

```
$ java -version
openjdk version "11.0.11" 2021-04-20
OpenJDK Runtime Environment (build 11.0.11+9-post-Debian-1deb10u1)
OpenJDK 64-Bit Server VM (build 11.0.11+9-post-Debian-1deb10u1, mixed mode, sharing)
```

我们在`pomx.ml`中指定要使用 Java 16。这个问题可以通过下载 Java 16 并设置`JAVA_HOME`环境变量来解决。

注意

我们有解决这个问题的正确工具，**SDKMAN**，可以从 [`sdkman.io/`](https://sdkman.io/) 访问。它允许您并行使用多个版本的 **Java JDK**。查看支持的 JDK（[`sdkman.io/jdks`](https://sdkman.io/jdks)）和 SDK（[`sdkman.io/sdks`](https://sdkman.io/sdks)）。随着新的六个月发布周期，我们每六个月就会获得一个新的 JDK。作为开发人员，我们喜欢尝试和探索这些功能，通过手动下载并更改 `JAVA_HOME` 来切换到不同的 JDK。整个过程都是手动的，而使用 `SDKMAN`，我们只需运行一个命令来下载您选择的 JDK，下载完成后，它甚至会将 `JAVA_HOME` 更新为最新下载的 JDK。很酷，不是吗？

1.  让我们尝试使用 SDKMAN 安装 JDK16。请注意，您不必在云 Shell 预配的 VM 实例中安装 SDKMAN，因为它已经预装。现在在 CLI 中输入 `sdk`，它将显示支持的命令：![图 8.41 – SDKMAN 命令帮助](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.41_B17385.jpg)

图 8.41 – SDKMAN 命令帮助

要了解不同支持的 JDK，请运行 `sdk list java` 命令。在下面的截图中，您将无法看到所有支持的 JDK 供应商，但您可以了解到大致情况：

![图 8.42 – SDKMAN 支持的 JDK](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.42_B17385.jpg)

图 8.42 – SDKMAN 支持的 JDK

要下载特定供应商的 JDK，请运行 `sdk install java Identifier` 命令。在我们的情况下，实际命令将是 `sdk install java 16-open`，因为我们决定使用 Java 16 的 OpenJDK 构建。

![图 8.43 – 安装 JDK16](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.43_B17385.jpg)

图 8.43 – 安装 JDK16

您可能还想要运行以下命令来更改活动 shell 会话中的 JDK：

```
$ sdk use java 16-open
Using java version 16-open in this shell.
```

1.  让我们再次通过运行 `./mvnw clean compile` 命令来编译项目。在下面的输出中，您可以看到构建成功：![图 8.44 – Maven 构建成功](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.44_B17385.jpg)

图 8.44 – Maven 构建成功

1.  我们准备好从 Cloud Shell 运行命令，将 Spring Boot 应用部署到远程 GKE 集群。在此之前，请确保您的 Kubernetes 上下文已设置为远程集群。如果不确定，请通过运行`kubectl config current-context`命令进行验证。如果未设置，则使用`gcloud container clusters get-credentials gke-autopilot-cluster1 --region us-east1`命令进行设置，这将在`kubeconfig`文件中添加条目。

1.  在最后一步，我们只需运行`skaffold run --default-repo=gcr.io/<PROJECT_ID>`命令。部署已稳定，最终输出将与上一节中*步骤 13*中看到的相同。

![图 8.45 - Skaffold 运行输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_8.45_B17385.jpg)

图 8.45 - Skaffold 运行输出

使用基于浏览器的 Cloud Shell 环境完成了将 Spring Boot 应用部署到远程 GKE 集群的过程。我们学会了如何利用基于浏览器的预配置 Cloud Shell 环境进行开发。如果您想尝试和尝试一些东西，那么这是 Google 提供的一个很好的功能。但是，我不确定您是否应该将其用于生产用例。使用 Cloud Shell 提供的 Google Compute Engine VM 实例是基于每个用户、每个会话的基础提供的。如果您的会话处于活动状态，您的 VM 实例将持续存在；否则，它们将被丢弃。有关 Cloud Shell 工作原理的信息，请阅读官方文档：

[`cloud.google.com/shell/docs/how-cloud-shell-works`](https://cloud.google.com/shell/docs/how-cloud-shell-works)

# 总结

在本章中，我们首先讨论了使用云供应商的功能和优势。然后，我们向您介绍了 GCP。首先，我们详细介绍了如何加入 Cloud 平台。接下来，我们介绍了 Google Cloud SDK，它允许您执行各种任务，如安装组件、创建 Kubernetes 集群以及启用不同的服务，如 Google 容器注册表等。

我们还讨论了基于浏览器的 Cloud Shell 编辑器，它由 Google Compute Engine VM 实例提供支持。您可以将其用作临时沙盒环境，以测试 GCP 支持的各种服务。然后，我们介绍了使用 Cloud SDK 和 Cloud Console 创建 Kubernetes 集群的两种不同方式。之后，我们向您介绍了无服务器 Kubernetes 提供的 GKE Autopilot，并介绍了其特点和优势，以及与标准 Kubernetes 集群相比的优势。最后，我们使用 Skaffold 从本地成功将 Spring Boot 应用程序部署到 GKE Autopilot 集群，然后在最后一节中使用 Google Cloud Shell。

在本章中，您已经获得了有关 GCP 托管的 Kubernetes 服务以及 Cloud SDK 和 Cloud Shell 等工具的实际知识。您还学会了如何使用 Skaffold 将 Spring Boot 应用程序部署到远程 Kubernetes 集群。

在下一章中，我们将学习如何使用 GitHub actions 和 Skaffold 创建 CI/CD 流水线。

# 进一步阅读

+   了解有关 GKE 自动驾驶的更多信息：[`cloud.google.com/blog/products/containers-kubernetes/introducing-gke-autopilot`](https://cloud.google.com/blog/products/containers-kubernetes/introducing-gke-autopilot)

+   了解有关 Google Cloud 平台的更多信息：[`cloud.google.com/docs`](https://cloud.google.com/docs)

+   面向架构师的 Google Cloud 平台：[`www.packtpub.com/product/google-cloud-platform-for-architects/9781788834308`](https://www.packtpub.com/product/google-cloud-platform-for-architects/9781788834308)
