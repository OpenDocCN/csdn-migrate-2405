# PHP 微服务（三）

> 原文：[`zh.annas-archive.org/md5/32377e38e7a2e12adc56f6a343e595a0`](https://zh.annas-archive.org/md5/32377e38e7a2e12adc56f6a343e595a0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：监控

在上一章中，我们花了一些时间开发我们的示例应用程序。现在是时候开始更高级的主题了。在本章中，我们将向您展示如何监视您的微服务应用程序。跟踪应用程序中发生的一切将帮助您随时了解整体性能，甚至可以找到问题和瓶颈。

# 调试和性能分析

在开发复杂和大型应用程序时，调试和性能分析是非常必要的，因此让我们解释一下它们是什么，以及我们如何利用这些工具。

## 什么是调试？

调试是识别和修复编程错误的过程。这主要是一个手动任务，开发人员需要运用他们的想象力、直觉，并且需要有很多耐心。

大多数情况下，需要在代码中包含新的指令，以在执行的具体点或代码中读取变量的值，或者停止执行以了解它是否通过函数。

然而，这个过程可以由调试器来管理。这是一个工具或应用程序，允许我们控制应用程序的执行，以便跟踪每个执行的指令并找到错误，避免必须在我们的代码中添加代码指令。

调试器使用一个称为断点的指令。**断点**就像它的名字所暗示的那样，是应用程序停止的一个点，以便由开发人员决定要做什么。在那一点上，调试器会提供有关应用程序当前状态的不同信息。

我们稍后将更多地了解调试器和断点。

## 什么是性能分析？

像调试一样，性能分析是一个过程，用于确定我们的应用在性能方面是否正常工作。性能分析调查应用程序的行为，以了解执行不同代码部分所需的专用时间，以找到瓶颈或在速度或消耗资源方面进行优化。

性能分析通常在开发过程中作为调试的一部分使用，并且需要由专家在适当的环境中进行测量，以获得真实的数据。

有四种不同类型的性能分析器：基于事件的、统计的、支持代码的工具和模拟的。

## 使用 Xdebug 在 PHP 中进行调试和性能分析

现在我们将在我们的项目中安装和设置 Xdebug。这必须安装在我们的 IDE 上，因此取决于您使用的是哪个，此过程将有所不同，但要遵循的步骤相当相似。在我们的情况下，我们将在 PHPStorm 上安装它。即使您使用不同的 IDE，在安装 Xdebug 之后，在任何 IDE 中调试代码的工作流程基本上是相同的。

### 调试安装

在我们的 Docker 上安装 Xdebug，我们应该修改适当的`Dockerfile`文件。我们将在用户微服务上安装它，所以打开`docker/microservices/user/php-fpm/Dockerfile`文件，并添加以下突出显示的行：

```php
**FROM php:7-fpm**
**RUN apt-get update && apt-get -y install** 
**git g++ libcurl4-gnutls-dev libicu-dev libmcrypt-dev libpq-dev libxml2-dev unzip zlib1g-dev** 
**&& git clone -b php7 https://github.com/phpredis/phpredis.git /usr/src/php/ext/redis** 
**&& docker-php-ext-install curl intl json mbstring mcrypt pdo pdo_mysql redis xml** 
**&& apt-get autoremove && apt-get autoclean** 
**&& rm -rf /var/lib/apt/lists/***
**RUN apt-get update && apt-get upgrade -y && apt-get autoremove -y** 
**&& apt-get install -y git libmcrypt-dev libpng12-dev libjpeg-dev libpq-dev mysql-client curl** 
**&& rm -rf /var/lib/apt/lists/*** 
**&& docker-php-ext-configure gd --with-png-dir=/usr --with-jpeg-dir=/usr** 
**&& docker-php-ext-install mcrypt gd mbstring pdo pdo_mysql zip** 
**&& pecl install xdebug** 
**&& rm -rf /tmp/pear** 
**&& echo "zend_extension=$(find /usr/local/lib/php/extensions/ -name xdebug.so)n" >> /usr/local/etc/php/conf.d/xdebug.ini** 
**&& echo "xdebug.remote_enable=on" >> /usr/local/etc/php/conf.d/xdebug.ini** 
**&& echo "xdebug.remote_autostart=off" >> /usr/local/etc/php/conf.d/xdebug.ini** 
**&& echo "xdebug.remote_port=9000" >> /usr/local/etc/php/conf.d/xdebug.ini** 
**&& curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer**
**RUN echo 'date.timezone="Europe/Madrid"' >> /usr/local/etc/php/conf.d/date.ini
RUN echo 'session.save_path = "/tmp"' >> /usr/local/etc/php/conf.d/session.ini

{{ Omited code }}

RUN curl -sSL https://phar.phpunit.de/phpunit.phar -o /usr/bin/phpunit && chmod +x /usr/bin/phpunit

ADD ./config/php.ini /usr/local/etc/php/
CMD [ "/usr/local/bin/containerpilot", 
"php-fpm", 
"--nodaemonize"]**

```

第一个突出显示的块是`安装 xdebug`所必需的。`&& pecl install xdebug`行用于使用 PECL 安装 Xdebug，其余行设置了`xdebug.ini`文件上的参数。第二个是将`php.ini`文件从我们的本地机器复制到 Docker。

还需要在`php.ini`文件上设置一些值，因此打开它，它位于`docker/microservices/user/php-fpm/config/php.ini`，并添加以下行：

```php
    memory_limit = 128M
    post_max_size = 100M
    upload_max_filesize = 200M

    [Xdebug]
    xdebug.remote_host=**YOUR_LOCAL_IP_ADDRESS**

```

您应该输入您的本地 IP 地址，而不是`YOUR_LOCAL_IP_ADDRESS`，以便在 Docker 中可见，因此 Xdebug 将能够读取我们的代码。

### 提示

您的本地 IP 地址是您网络内部的 IP，而不是公共 IP。

现在，您可以通过执行以下命令进行构建，以安装调试所需的一切：

```php
**docker-compose build microservice_user_fpm**

```

这可能需要几分钟。一旦完成，Xdebug 将被安装。

### 调试设置

现在是时候在我们喜爱的 IDE 上设置 Xdebug 了。正如我们之前所说，我们将使用 PHPStorm，但是请随意使用任何其他 IDE。

我们必须在 IDE 上创建一个服务器，在 PHPStorm 中，可以通过导航到**首选项** | **语言和框架** | **PHP**来完成。因此，添加一个新的，并将`name`设置为`users`，例如，`host`设置为`localhost`，`port`设置为`8084`，`debugger`设置为`xdebug`。还需要启用**使用路径映射**以便映射我们的路由。

现在，我们需要导航到**工具** | **DBGp 代理配置**，确保 IDE 密钥字段设置为`PHPSTORM`，`Host`设置为`users`（这个名称必须与你在服务器部分输入的名称相同），`Port`设置为`9000`。

通过执行以下命令停止和启动 Docker：

```php
**docker-compose stop**
**docker-compose up -d**

```

设置 PHPStorm 能够像调试器一样监听：

![调试设置](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_06_01.jpg)

PHPStorm 中监听连接的 Xdebug 按钮

### 调试输出

现在你已经准备好查看调试器的结果。你只需要在你的代码中设置断点，执行将在那一点停止，给你所有的数据值。要做到这一点，转到你的代码，例如，在`UserController.php`文件中，并点击一行的左侧。它会创建一个红点；这是一个断点：

![调试输出](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_06_02.jpg)

在 PHPStorm 中设置断点

现在，你已经设置了断点并且调试器正在运行，所以现在是时候用 Postman 发起一个调用来尝试调试器了。通过执行一个 POST 调用到`http://localhost:8084/api/v1/user`，参数为`api_key = RSAy430_a3eGR 和 XDEBUG_SESSION_START = PHPSTORM`。执行将在断点处停止，从那里开始你就有了执行控制：

![调试输出](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_06_03-1.jpg)

PHPStorm 中的调试器控制台

注意你在变量侧的所有参数的当前值。在这种情况下，你可以看到`test`参数设置为`"this is a test"`；我们在断点之前的两行分配了这个值。

正如我们所说，现在我们控制了执行；三个基本功能如下：

1.  **步过：** 这将继续执行下一行。

1.  **步入：** 这将在函数内部继续执行。

1.  **步出：** 这将在函数外部继续执行。

所有这些基本功能都是逐步执行的，所以它将在下一行停止，不需要任何其他断点。

正如你所看到的，这对于找到代码中的错误非常有用。

### 性能分析安装

一旦我们安装了 Xdebug，我们只需要在`docker/microservices/user/php-fpm/Dockerfile`文件中添加以下行以启用性能分析：

```php
**RUN apt-get update && apt-get upgrade -y && apt-get autoremove -y 
&& apt-get install -y git libmcrypt-dev libpng12-dev libjpeg-dev libpq-dev mysql-client curl 
&& rm -rf /var/lib/apt/lists/* 
&& docker-php-ext-configure gd --with-png-dir=/usr --with-jpeg-dir=/usr 
&& docker-php-ext-install mcrypt gd mbstring pdo pdo_mysql zip 
&& pecl install xdebug 
&& rm -rf /tmp/pear 
&& echo "zend_extension=$(find /usr/local/lib/php/extensions/ -name xdebug.so)n" >> /usr/local/etc/php/conf.d/xdebug.ini 
&& echo "xdebug.remote_enable=onn" >> /usr/local/etc/php/conf.d/xdebug.ini 
&& echo "xdebug.remote_autostart=offn" >> /usr/local/etc/php/conf.d/xdebug.ini 
&& echo "xdebug.remote_port=9000n" >> /usr/local/etc/php/conf.d/xdebug.ini**
**&& echo "xdebug.profiler_enable=onn" >> /usr/local/etc/php/conf.d/xdebug.ini** 
**&& echo "xdebug.profiler_output_dir=/var/www/html/tmpn" >> /usr/local/etc/php/conf.d/xdebug.ini** 
**&& echo "xdebug.profiler_enable_trigger=onn" >> /usr/local/etc/php/conf.d/xdebug.ini** 
**&& curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer**

```

通过`profiler_enable`，我们启用了性能分析器，并且输出目录由`profiler_output_dir`设置。这个目录应该存在于我们的用户微服务中，以便获取性能分析器输出文件。因此，如果还没有创建，请在`/source/user/tmp`上创建。

现在，你可以通过执行以下命令进行构建，以安装调试所需的一切：

```php
**docker-compose build microservice_user_fpm**

```

这可能需要几分钟。一旦完成，Xdebug 就会被安装。

### 性能分析设置

它不需要设置，所以只需通过执行以下命令停止和启动 Docker：

```php
**docker-compose stop**
**docker-compose up -d**

```

设置 PHPStorm 能够像调试器一样监听。

### 分析输出文件

为了生成性能分析文件，我们需要执行一个调用，就像之前在 Postman 中做的那样，所以随时执行你想要的方法。它将在我们之前创建的文件夹中生成一个名为`cachegrind.out.XX`的文件。

如果你打开这个文件，你会注意到它很难理解，但有一些工具可以读取这种类型的内容。PHPStorm 有一个工具位于**工具** | **分析** Xdebug Profiler Snapshot**。一旦打开它，你可以选择要分析的文件，然后工具将向你展示所有文件和函数在调用中执行的详细分析。显示花费的时间，调用的次数，以及其他有趣的东西非常有用，可以优化你的代码并找到瓶颈。

# 错误处理

错误处理是我们管理应用程序中的错误和异常的方式。这对于检测和组织开发中可能发生的所有可能的错误非常重要。

## 什么是错误处理？

术语*错误处理*在开发中用于指代在执行过程中响应异常发生的过程。

通常，异常的出现会打断应用程序执行的正常工作流程，并执行注册的异常处理程序，为我们提供更多关于发生了什么以及有时如何避免异常的信息。

PHP 处理错误的方式非常基础。默认的错误消息由文件名、行号和关于浏览器接收到的错误的简短描述组成。在本章中，我们将看到三种不同的处理错误的方式。

## 为什么错误处理很重要？

大多数应用程序非常复杂和庞大，它们也是由不同的人甚至不同的团队开发的，如果我们正在开发基于微服务的应用程序，那么这些团队可能会更多。想象一下，如果我们混合所有这些东西，项目中可能出现的潜在错误有多少？要意识到应用程序可能存在的所有可能问题或用户可能在其中发现的问题是不可能的。

因此，错误处理以以下两种方式帮助：

+   **用户或消费者**：在微服务中，错误处理非常有用，因为它允许消费者知道 API 可能存在的问题，也许他们可以弄清楚这是否与 API 调用中引入的参数有关，或者与图像文件大小有关。此外，在微服务中，使用不同的错误状态代码对于让消费者知道发生了什么是非常有用的。您可以在第十一章*最佳实践和约定*中找到这些代码。

在商业网站上，错误处理可以避免向用户或客户显示诸如`PHP 致命错误：无法访问空属性`之类的奇怪消息。而是可以简单地说`出现错误，请与我们联系`。

+   **开发人员或您自己**：它可以让团队的其他成员甚至您自己意识到应用程序中的任何错误，帮助您调试可能出现的问题。有许多工具可以获取这些类型的错误并通过电子邮件将它们发送给您，写入日志文件，或者放在事件日志中，详细说明错误跟踪、函数参数、数据库调用等更有趣的事情。

## 在微服务中管理错误处理时的挑战

如前所述，我们将解释三种不同的处理错误的方式。当我们使用微服务时，我们必须监视所有可能的错误，以便让微服务知道问题所在。

### 基本的 die()函数

在 PHP 中，处理错误的基本方法是使用 die()命令。让我们来看一个例子。假设我们想要打开一个文件：

```php
    <?php
      $file=fopen("test.txt","r");
    ?>
```

当执行到达那一点并尝试打开名为`test.txt`的文件时，如果文件不存在，PHP 会抛出这样的错误：

```php
**Warning: fopen(test.txt) [function.fopen]: failed to open stream:
No such file or directory in /var/www/html/die_example.php on line 2**

```

为了避免错误消息，我们可以使用`die()`函数，并在其中写上原因，以便执行不会继续：

```php
    <?php
      if(!file_exists("test.txt")) {
        die("The file does not exist");
      } else {
        $file=fopen("test.txt","r");
      }
    ?>
```

这只是 PHP 中基本错误处理的一个例子。显然，有更好的方法来处理这个问题，但这是管理错误所需的最低限度。换句话说，避免 PHP 应用程序的自动错误消息比手动停止执行并向用户提供人类语言的原因更有效。

让我们来看一个替代的管理方式。

### 自定义错误处理

创建一个系统来管理应用程序中的错误比使用`die()`函数更好。Lumen 为我们提供了这个系统，并且在安装时已经配置好了。

我们可以通过设置其他参数来配置它。首先是错误详情。通过将其设置为`true`，可以获取有关错误的更多信息。为此，需要在你的`.env`文件中添加`APP_DEBUG`值并将其设置为`true`。这是在开发环境中工作的推荐方式，这样开发人员可以更多地了解应用程序的问题，但一旦应用程序部署到生产服务器上，这个值应该设置为`false`，以避免向用户提供更多信息。

这个系统通过`AppExceptionsHandler`类来管理所有的异常。这个类包含两个方法：`report`和`render`。让我们来解释一下它们。

#### 报告方法

`Report`方法用于记录在你的微服务中发生的异常，甚至可以将它们发送到 Sentry 等外部工具。我们将在本章中详细介绍这一点。

正如前面提到的，这个方法只是在基类上记录问题，但你可以按照自己的需求管理不同的异常。看看下面的例子，你可以如何做到这一点：

```php
    public function report(Exception $e)
    {
      if ($e instanceof CustomException) {
        //
      } else if ($e instanceof OtherCustomException) {
        //
      }
      return parent::report($e);
    }
```

管理不同错误的方法是`instanceof`。正如你所看到的，在前面的例子中，你可以针对每种异常类型有不同的响应。

还可以通过向`$dontReport`类添加一个变量来忽略一些异常类型。这是一个你不想报告的不同异常的数组。如果我们在`Handle`类上不使用这个变量，那么默认情况下只有`404`错误会被忽略。

```php
    protected $dontReport = [
      HttpException::class,
      ValidationException::class
    ];
```

#### 渲染方法

如果`report`方法用于帮助开发者或你自己，那么渲染方法是用来帮助用户或消费者的。这个方法会将异常以 HTTP 响应的形式返回给用户（如果是网站）或者返回给消费者（如果是 API）。

默认情况下，异常被发送到基类以生成响应，但可以进行修改。看看这段代码：

```php
    public function render($request, Exception $e)
    {
      if ($e instanceof CustomException) {
        return response('Custom Message');
      }
      return parent::render($request, $e);
    }
```

正如你所看到的，`render`方法接收两个参数：请求和异常。通过这些参数，你可以为你的用户或消费者做出适当的响应，提供你想要为每个异常提供的信息。例如，通过在 API 文档中给消费者一个错误代码，他们可以在 API 文档中查看。看下面的例子：

```php
    public function render($request, Exception $e)
    {
      if ($e instanceof CustomException) {
        return response()->json([
            'error' => $e->getMessage(),
            'code' => 44 ,
          ],
        Response::HTTP_UNPROCESSABLE_ENTITY);
      }
      return parent::render($request, $e);
    }
```

消费者将收到一个带有`代码 44`的错误消息；这应该在我们的 API 文档中，以及适当的状态码。显然，这可能会因消费者的需求而有所不同。

### 使用 Sentry 进行错误处理

拥有一个监控错误的系统甚至更好。市场上有很多错误跟踪系统，但其中一个脱颖而出的是 Sentry，它是一个实时的跨平台错误跟踪系统，为我们提供了理解微服务中发生的情况的线索。一个有趣的特性是它支持通过电子邮件或其他媒介进行通知。

使用一个知名的系统有利于你的应用，你正在使用一个值得信赖和知名的工具，而在我们的情况下，它与我们的框架 Lumen 有着简单的集成。

我们需要做的第一件事是在我们的 Docker 环境中安装 Sentry；所以，像往常一样，停止所有的容器，使用`docker-compose stop`。一旦所有的容器都停止了，打开`docker-compose.yml`文件并添加以下容器：

```php
    sentry_redis:
      image: redis
    expose:
      - 6379

    sentry_postgres:
      image: postgres
      environment:
        - POSTGRES_PASSWORD=sentry
        - POSTGRES_USER=sentry
      volumes:
        - /var/lib/postgresql/data
      expose:
        - 5432

      sentry:
        image: sentry
      links:
        - sentry_redis
        - sentry_postgres
      ports:
        - 9876:9000
      environment:
        SENTRY_SECRET_KEY: mymicrosecret
        SENTRY_POSTGRES_HOST: sentry_postgres
        SENTRY_REDIS_HOST: sentry_redis
        SENTRY_DB_USER: sentry
        SENTRY_DB_PASSWORD: sentry

      sentry_celery-beat:
        image: sentry
      links:
        - sentry_redis
        - sentry_postgres
        command: sentry celery beat
      environment:
        SENTRY_SECRET_KEY: mymicrosecret
        SENTRY_POSTGRES_HOST: sentry_postgres
        SENTRY_REDIS_HOST: sentry_redis
        SENTRY_DB_USER: sentry
        SENTRY_DB_PASSWORD: sentry

      sentry_celery-worker:
        image: sentry
      links:
        - sentry_redis
        - sentry_postgres
        command: sentry celery worker
      environment:
        SENTRY_SECRET_KEY: mymicrosecret
        SENTRY_POSTGRES_HOST: sentry_postgres
        SENTRY_REDIS_HOST: sentry_redis
        SENTRY_DB_USER: sentry
        SENTRY_DB_PASSWORD: sentry
```

在上面的代码中，我们首先创建了一个特定的`redis`和`postgresql`容器，这将被 Sentry 使用。一旦我们有了所需的数据存储容器，我们就添加并链接了 Sentry 核心的不同容器。

```php
**docker-compose up -d sentry_redis sentry_postgres sentry**

```

上述命令将启动我们设置 Sentry 所需的最小容器。一旦我们第一次启动它们，我们需要配置和填充数据库和用户。我们可以通过在我们为 Sentry 可用的容器上运行一个命令来完成：

```php
**docker exec -it docker_sentry_1 sentry upgrade**

```

上述命令将完成 Sentry 运行所需的所有设置，并要求您创建一个帐户以作为管理员访问 UI；保存并稍后使用。一旦完成并返回到命令路径，您可以启动我们项目的其余容器：

```php
**docker-compose up -d**

```

一切准备就绪后，您可以在浏览器中打开`http://localhost:9876`，您将看到类似以下的屏幕：

![使用 Sentry 处理错误](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_06_03-1.jpg)

Sentry 登录页面

使用在上一步中创建的用户登录，并创建一个新项目来开始跟踪我们的错误/日志。

### 提示

不要使用单个 Sentry 项目来存储所有的调试信息，最好将它们分成逻辑组，例如，一个用于用户微服务 API 等。

创建项目后，您将需要分配给该项目的 DSN；打开项目设置并选择**客户端密钥**选项。在此部分，您可以找到分配给项目的**DSN**密钥；您将在您的代码中使用这些密钥，以便库知道需要发送所有调试信息的位置：

![使用 Sentry 处理错误](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_06_05.jpg)

Sentry DSN 密钥

恭喜！此时，您已经准备好在项目中使用 Sentry。现在是时候使用 composer 安装`sentry/sentry-laravel`包了。要安装此库，您可以编辑您的`composer.json`文件，或者使用以下命令进入您的用户微服务容器：

```php
**docker exec -it docker_microservice_user_fpm_1 /bin/bash**

```

一旦您进入容器，使用以下命令使用 composer 更新您的`composer.json`并为您安装：

```php
**composer require sentry/sentry-laravel**

```

安装完成后，我们需要在我们的微服务上进行配置，因此打开`bootstrap/app.php`文件并添加以下行：

```php
**$app->register('SentrySentryLaravelSentryLumenServiceProvider');**
# Sentry must be registered before routes are included
require __DIR__ . '/../app/Http/routes.php';
```

现在，我们需要像之前看到的那样配置报告方法，因此转到`app/Exceptions/Handler.php`文件，并在报告函数中添加以下行：

```php
    public function report(Exception $e)
    {
       if ($this->shouldReport($e)) {
         app('sentry')->captureException($e);
       }
       parent::report($e);
    }
```

这些行将向 Sentry 报告异常，因此让我们创建`config/sentry.php`文件，并进行以下配置：

```php
    <?php
      return array(
        'dsn' => '___DSN___',
        'breadcrumbs.sql_bindings' => true,
      );
```

# 应用程序日志

日志是调试信息的记录，将来可能对查看应用程序的性能或查看应用程序的运行情况或甚至获取一些统计信息非常重要。实际上，几乎所有已知的应用程序都会产生某种日志信息。例如，默认情况下，所有对 NGINX 的请求都记录在`/var/log/nginx/error.log`和`/var/log/nginx/access.log`中。第一个`error.log`存储应用程序生成的任何错误，例如 PHP 异常。第二个`access.log`由每个命中 NGINX 服务器的请求创建。

作为一名经验丰富的开发人员，您已经知道在应用程序中保留一些日志非常重要，并且您并不孤单，您可以找到许多可以让您的生活更轻松的库。您可能想知道重要的地方在哪里，以及您可以放置日志调用和您需要保存的信息。没有一成不变的规则，您只需要考虑未来，以及在最坏的情况下（应用程序崩溃）您将需要哪些信息。

让我们专注于我们的示例应用程序；在用户服务中，我们将处理用户注册。您可以在保存新用户注册之前放置一个日志调用的有趣点。通过这样做，您可以跟踪您的日志，并知道我们正在尝试保存和何时保存的信息。现在，假设注册过程中有一个错误，并且在使用特殊字符时出现问题，但您并不知道这一点，您唯一知道的是有一些用户报告了注册问题。现在你会怎么做？检查日志！您可以轻松地检查用户正在尝试存储的信息，并发现使用特殊字符的用户没有被注册。

例如，如果您没有使用日志系统，可以使用`error_log()`将消息存储在默认日志文件中：

```php
**error_log('Your log message!', 0);**

```

参数`0`表示我们要将消息存储在默认日志文件中。此函数允许我们通过电子邮件发送消息，将`0`参数更改为`1`并添加一个额外的参数，其中包含电子邮件地址。

所有的日志系统都允许您定义不同的级别；最常见的是（请注意，它们在不同的日志系统中可能有不同的名称，但概念是相同的）：

+   **信息**：这指的是非关键信息。通常，您可以使用此级别存储调试信息，例如，您可以在特定页面呈现时存储一个新记录。

+   **警告**：这些是不太重要或系统可以自行恢复的错误。例如，缺少某些信息可能会导致应用程序处于不一致的状态。

+   **错误**：这是关键信息，当然，所有这些都是发生在您的应用程序中的错误。这是您在发现错误时将首先检查的级别。

## 微服务中的挑战

当您使用单体应用程序时，您的日志将默认存储在相同位置，或者至少在只有几台服务器上。如果出现任何问题，您需要检查日志，您可以在几分钟内获取所有信息。挑战在于当您处理微服务架构时，每个微服务都会生成日志信息。如果您有多个微服务实例，每个实例都会创建自己的日志数据，情况会变得更糟。

在这种情况下，您会怎么做？答案是使用像 Sentry 这样的日志系统将所有日志记录存储在同一位置。拥有日志服务可以让您扩展基础架构而不必担心日志。它们将全部存储在同一位置，让您轻松地找到有关不同微服务/实例的信息。

## Lumen 中的日志

Lumen 默认集成了**Monolog**（PSR-3 接口）；这个日志库允许您使用不同的日志处理程序。

在 Lumen 框架中，您可以在`.env`文件中设置应用程序的错误详细信息。`APP_DEBUG`设置定义了将生成多少调试信息。主要建议是在开发环境中将此标志设置为`true`，但在生产环境中始终设置为`false`。

要在代码中使用日志记录功能，您只需要确保已取消注释`bootstrap/app.php`文件中的`$app->withFacades();`行。一旦启用了门面，您就可以在代码的任何地方开始使用 Log 类。

### 提示

默认情况下，没有任何额外配置，Lumen 将日志存储在`storage/logs`文件夹中。

我们的记录器提供了 RFC 5424 中定义的八个日志级别：

+   `Log::emergency($error);`

+   `Log::alert($error);`

+   `Log::critical($error);`

+   `Log::error($error);`

+   `Log::warning($error);`

+   `Log::notice($error);`

+   `Log::info($error);`

+   `Log::debug($error);`

一个有趣的功能是您必须添加一个上下文数据数组的选项。想象一下，您想记录一个失败的用户登录记录。您可以执行类似以下代码的操作：

```php
    Log::info('User unable to login.', ['id' => $user->id]);
```

在上述代码片段中，我们正在向我们的日志消息添加额外信息--尝试登录到我们的应用程序时出现问题的用户的 ID。

使用像 Sentry 这样的自定义处理程序设置 Monolog（我们之前解释了如何在项目中安装它）非常容易，您只需要将以下代码添加到`bootstrap/app.php`文件中：

```php
    $app->configureMonologUsing(function($monolog) {
      $client = new Raven_Client('sentry-dsn');
      $monolog->pushHandler(
        new MonologHandlerRavenHandler($client, 
                                       MonologLogger::WARNING)
      );
      return $monolog;
    });
```

上述代码更改了 Monolog 的工作方式；在我们的情况下，它将不再将所有调试信息存储在`storage/logs`文件夹中，而是使用我们的 Sentry 安装和`WARNING`级别。

我们向您展示了在 Lumen 中存储日志的两种不同方式：像单体应用程序一样在本地文件中存储，或者使用外部服务。这两种方式都可以，但我们建议微服务开发使用像 Sentry 这样的外部工具。

# 应用程序监控

在软件开发中，应用程序监控可以被定义为确保我们的应用程序以预期的方式执行的过程。这个过程允许我们测量和评估我们的应用程序的性能，并有助于发现瓶颈或隐藏的问题。

应用程序监控通常是通过专门的软件进行的，该软件从运行您的软件的应用程序或基础架构中收集指标。这些指标可以包括 CPU 负载、事务时间或平均响应时间等。您可以测量的任何内容都可以存储在遥测系统中，以便以后进行分析。

监控单体应用程序很容易；您可以在一个地方找到所有内容，所有日志都存储在同一个地方，所有指标都可以从同一主机收集，您可以知道您的 PHP 线程是否在消耗服务器资源。您可能遇到的主要困难是找到应用程序中性能不佳的部分，例如，您的 PHP 代码中的哪一部分在浪费资源。

当您使用微服务时，您的代码被分割成逻辑部分，使您能够知道应用程序的哪一部分性能不佳，但代价很大。您的所有指标被分隔在不同的容器或服务器之间，这使得很难获得整体性能的全貌。通过建立遥测系统，您可以将所有指标发送到同一位置，从而更容易地检查和调试您的应用程序。

## 按层次监控

作为开发人员，您需要了解您的应用程序在各个层面的表现，从顶层即您的应用程序到底层即硬件或虚拟化层。在理想的情况下，我们将能够控制所有层面，但最有可能的情况是您只能监控到基础架构层。

以下图片显示了不同层次和与服务器堆栈的关系：

![按层次监控](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_06_06.jpg)

监控层

### 应用程序级别

应用程序级别存在于您的应用程序内；所有指标都是由您的代码生成的，例如我们的 PHP。不幸的是，您无法找到专门用于 PHP 的**应用程序性能监控**（**APM**）的免费或开源工具。无论如何，您可以找到有趣的第三方服务，并尝试其免费计划。

PHP 的两个最知名的 APM 服务是 New Relic 和 Datadog。在这两种情况下，安装都遵循相同的路径--您在容器/主机上安装一个代理（或库），这个小软件将开始将指标发送到其服务，为您提供一个仪表板，您可以在其中操作您的数据。使用第三方服务的主要缺点是您无法控制该代理或指标系统，但这个缺点可以转化为一个优点--您将拥有一个可靠的系统，无需管理，您只需要关注您的应用程序。

#### Datadog

Datadog 客户端的安装非常简单。打开其中一个微服务的`composer.json`文件，并在`required`定义中添加以下行：

```php
    "datadog/php-datadogstatsd": "0.3.*"
```

保存更改并进行 composer 更新后，您就可以在代码中使用`Datadogstatsd`类并开始发送指标了。

想象一下，您想监控您的秘密微服务在获取数据库中所有服务器所花费的时间。打开您的秘密微服务的`app/Http/Controllers/SecretController.php`文件，并修改您的类，如下所示：

```php
    use Datadogstatsd;

    /** … Code omitted ... **/
    const APM_API_KEY = 'api-key-from-your-account';
    const APM_APP_KEY = 'app-key-from-your-account';

    public function index(Manager $fractal, SecretTransformer                          
    $secretTransformer, Request $request)
    {
      Datadogstatsd::configure(self::APM_API_KEY, self::APM_APP_KEY);
      $startTime = microtime(true);
      $records = Secret::all();

      $collection = new Collection($records, $secretTransformer);
      $data = $fractal->createData($collection)->toArray();
      Datadogstatsd::timing('secrets.loading.time', microtime(true) -                              
      $startTime, [‘service’ => ‘secret’]);

      return response()->json($data);
    }
```

上述代码片段定义了你的应用程序和 Datadog 账户的 API 密钥，我们使用它们来设置我们的`Datadogstatsd`接口。这个例子记录了检索所有秘密记录所花费的时间。`Datadogstatsd::timing()`方法将指标发送到我们的外部遥测服务。在你的应用程序内部进行监控可以让你决定在你的代码中生成指标的位置。在监控这个级别时没有硬性规定，但你需要记住重要的是要知道你的应用程序在哪里花费了大部分时间，所以在你认为可能成为瓶颈的代码的每个地方添加指标（比如从另一个服务获取数据或从数据库获取数据）。

使用这个库，你甚至可以使用以下方法增加和减少自定义指标点：

```php
    Datadogstatsd::increment('another.data.point');
    Datadogstatsd::increment('my.data.point.with.custom.increment', .5);
    Datadogstatsd::increment('your.data.point', 1, ['mytag’' => 'value']);
```

他们三个增加了一个点：第一个将`another.data.point`增加了一个单位，第二个将我们的点增加了`0.5`，第三个增加了点，并且还向度量记录添加了自定义标签。

你也可以使用`Datadogstatsd::decrement()`来减少点，它与`::increment()`具有相同的语法。

### 基础设施级别

这个层控制着操作系统和你的应用程序之间的一切。在这一层添加一个监控系统可以让你知道你的容器是否使用了太多内存，或者特定容器的负载是否过高。你甚至可以跟踪你的应用程序的一些基本指标。

在高街上，有多种监控这个层的选项，但我们将给你一些有趣的项目。它们都是开源的，尽管它们使用不同的方法，但你可以将它们结合起来。

#### Prometheus

**Prometheus**是一个开源的监控和警报工具包，是在 SoundCloud 创建的，并且属于**Cloud Native Computing Foundation**的一部分。作为新生力量并不意味着它没有强大的功能。除其他外，我们可以强调以下主要功能：

+   通过 HTTP 拉取进行时间序列收集

+   通过服务发现（kubernetes、consul 等）或静态配置进行目标发现

+   带有简单图形支持的 Web 界面

+   强大的查询语言，允许你从数据中提取所有你需要的信息

使用 Docker 安装 Prometheus 非常简单，我们只需要为我们的遥测系统添加一个新的容器，并将其与我们的自动发现服务（Consul）进行链接。将以下行添加到`docker-compose.yml`文件中：

```php
    telemetry:
      build: ./telemetry/
      links:
        - autodiscovery
      expose:
        - 9090
      ports:
        - 9090:9090
```

在上述代码中，我们只告诉 Docker`Dockerfile`的位置，链接了没有自动发现容器的容器，并暴露和映射了一些端口。现在，是时候创建`telemetry/Dockerfile`文件，内容如下：

```php
**FROM prom/prometheus:latest
ADD ./etc/prometheus.yml /etc/prometheus/**

```

正如你所看到的，创建我们的遥测容器并不需要太多的工作；我们使用官方镜像并添加我们的 Prometheus 配置。创建`etc/prometheus.yml`配置，内容如下：

```php
    global:
      scrape_interval: 15s
      evaluation_interval: 15s
      external_labels:
      monitor: 'codelab-monitor'

    scrape_configs:
      - job_name: 'containerpilot-telemetry'

    consul_sd_configs:
      - server: 'autodiscovery:8500'
      services: ['containerpilot']
```

同样，设置非常简单，因为我们正在定义一些全局的抓取间隔和一个名为`containerpilot-telemetry`的作业，它将使用我们的自动发现容器，并监视存储在 consul 中以`containerpilot`名称宣布的所有服务。

Prometheus 有一个简单而强大的 Web 界面。打开`localhost:9090`，你就可以访问到这个工具收集的所有指标。创建一个图表非常简单，选择一个指标，Prometheus 会为你完成所有工作：

![Prometheus](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_06_07-1.jpg)

Prometheus 图形界面

此时，您可能会想知道如何声明指标。在前面的章节中，我们介绍了`containerpilot`，这是一个我们将在容器中用作 PID 来管理自动发现的工具。`containerpilot`具有声明指标以供支持的遥测系统使用的能力，例如 Prometheus。例如，如果您打开`docker/microservices/battle/nginx/config/containerpilot.json`文件，您可以找到类似以下代码的内容：

```php
    "telemetry": {
      "port": 9090,
      "sensors": [
        {
          "name": "nginx_connections_unhandled_total",
          "help": "Number of accepted connnections that were not 
                   handled",
          "type": "gauge",
          "poll": 5,
          "check": ["/usr/local/bin/sensor.sh", "unhandled"]
        },
        {
          "name": "nginx_connections_load",
          "help": "Ratio of active connections (less waiting) to the                   
                   maximum worker connections",
          "type": "gauge",
          "poll": 5,
          "check": ["/usr/local/bin/sensor.sh", "connections_load"]
        }
      ]
    }
```

在上述代码中，我们声明了两个指标：`"nginx_connections_unhandled_total"`和`"nginx_connections_load"`。`ContainerPilot`将在容器内部运行在`"check"`参数中定义的命令，并且结果将被 Prometheus 抓取。

您可以使用 Prometheus 监控基础架构中的任何内容，甚至是 Prometheus 本身。请随意更改我们的基本安装和设置，并将其调整为使用自动驾驶模式。如果 Prometheus 的 Web UI 不足以满足您的图形需求，并且您需要更多的功能和控制权，您可以轻松地将我们的遥测系统与 Grafana 连接起来，Grafana 是创建各种指标仪表板的最强大工具之一。

#### Weave Scope

**Weave Scope**是用于监视容器的工具，它与 Docker 和 Kubernetes 配合良好，并具有一些有趣的功能，将使您的生活更轻松。Scope 为您提供了对应用程序和整个基础架构的深入全面视图。使用此工具，您可以实时诊断分布式容器化应用程序中的任何问题。

忘记复杂的配置，Scope 会自动检测并开始监视每个主机、Docker 容器和基础架构中运行的任何进程。一旦获取所有这些信息，它将创建一个漂亮的地图，实时显示所有容器之间的互联关系。您可以使用此工具查找内存问题、瓶颈或任何其他问题。您甚至可以检查进程、容器、服务或主机的不同指标。您可以在 Scope 中找到的一个隐藏功能是能够从浏览器 UI 中管理容器、查看日志或附加终端。

部署 Weave Scope 有两种选择：独立模式，其中所有组件在本地运行，或作为付费云服务，您无需担心任何事情。独立模式作为特权容器在每个基础架构服务器内运行，并且具有从集群或服务器中收集所有信息并在 UI 中显示的能力。

安装非常简单-您只需要在每个基础架构服务器上运行以下命令：

```php
**sudo curl -L git.io/scope -o /usr/local/bin/scope
sudo chmod a+x /usr/local/bin/scope
scope launch**

```

一旦您启动了 Scope，请打开服务器的 IP 地址（如果您像我们一样在本地工作，则为 localhost）`http://localhost:4040`，您将看到类似于以下屏幕截图的内容：

![Weave Scope](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_06_08-1.jpg)

Weave Scope 容器图形可视化

上述图像是我们正在构建的应用程序的快照；在这里，您可以看到我们所有的容器及其之间的连接在特定时间点。试一试，当您调用我们不同的 API 端点时，您将能够看到容器之间的连接发生变化。

您能在我们的微服务基础架构中找到任何问题吗？如果可以，那么您是正确的。正如您所看到的，我们没有将一些容器连接到自动发现服务。Scope 帮助我们找到了一个可能的未来问题，现在请随意修复它。

正如您所看到的，您可以使用 Scope 从浏览器监视您的应用程序。您只需要注意谁可以访问特权 Scope 容器；如果您计划在生产中使用 Scope，请确保限制对此工具的访问。

### 硬件/虚拟化监控

这一层与我们的硬件或虚拟化层相匹配，是您可以放置指标的最低位置。这一层的维护和监控通常由系统管理员完成，他们可以使用非常知名的工具，如**Zabbix**或**Nagios**。作为开发人员，您可能不会担心这一层。如果您在云环境中部署应用程序，您将无法访问由这一层生成的任何指标。

# 摘要

在本章中，我们解释了如何调试和对微服务应用程序进行性能分析，这是软件开发中的重要过程。在日常工作中，您不会花费所有时间来调试或对应用程序进行性能分析；在某些情况下，您将花费大量时间来尝试修复错误。因此，重要的是要有一个地方可以存储所有错误和调试信息，这些信息将使您更深入地了解应用程序的情况。最后，作为全栈开发人员，我们向您展示了如何监视应用程序堆栈的顶部两层。


# 第七章：安全

当我们开发应用程序时，我们应该始终考虑如何使我们的微服务更加安全。有一些技术和方法，每个开发人员都应该了解，以避免安全问题。在本章中，您将发现如何在您的微服务中使用身份验证和授权，以及在用户登录后如何管理每个功能的权限。您还将发现可以用来加密数据的不同方法。

# 微服务中的加密

我们可以将加密定义为将信息转换为只有授权方能够阅读的过程。这个过程实际上可以在您的应用程序的任何级别进行。例如，您可以加密整个数据库，或者您可以在传输层使用 SSL/TSL 或**JSON Web Token**（**JWT**）进行加密。

如今，加密/解密过程是通过现代算法完成的，加密添加的最高级别是在传输层。在这一层中使用的所有算法至少提供以下功能：

+   **认证**：此功能允许您验证消息的来源

+   **完整性**：此功能可为您提供消息内容在从原始内容到目的地的过程中未更改的证据

加密算法的最终任务是为您提供一个安全层，以便您可以在不必担心有人窃取您的信息的情况下交换或存储敏感数据，但这并非免费。您的环境将使用一些资源来处理加密、解密或其他相关事项中的握手。

作为开发人员，您需要考虑到您将被部署到一个敌对的环境——生产环境是一个战区。如果您开始这样思考，您可能会开始问自己以下问题：

+   我们将部署到硬件还是虚拟化环境？我们将共享资源吗？

+   我们能相信我们应用程序的所有可能的邻居吗？

+   我们将把我们的应用程序分割成不同的和分离的区域吗？我们将如何连接我们的区域？

+   我们的应用程序是否符合 PCI 标准，或者由于我们存储/管理的数据，它是否需要非常高的安全级别？

当您开始回答所有这些问题（以及其他问题）时，您将开始确定应用程序所需的安全级别。

在本节中，我们将向您展示加密应用程序数据的最常见方法，以便您可以随后选择要实施的方法。

请注意，我们不考虑全盘加密，因为它被认为是保护数据的最弱方法。

## 数据库加密

当您处理敏感数据时，保护数据的最灵活且开销最低的方法是在应用程序层中使用加密。然而，如果由于某种原因您无法更改您的应用程序，接下来最强大的解决方案是加密您的数据库。

对于我们的应用程序，我们选择了*关系数据库*；具体来说，我们使用的是 Percona，一个 MySQL 分支。目前，您在该数据库中有两种不同的加密数据的选项：

+   通过 MariaDB 补丁启用加密（另一个与 Percona 非常相似的 MySQL 形式）。此补丁在 10.1.3 及更高版本中可用。

+   InnoDB 表空间级加密方法可从 Percona Server 5.7.11 或 MySQL 5.7.11 开始使用。

也许您想知道为什么我们在选择了 Percona 后还在谈论 MariaDB 和 MySQL。这是因为它们三者具有相同的核心，共享大部分核心功能。

### 提示

所有主要的数据库软件都允许您加密数据。如果您没有使用 Percona，请查看您的数据库的官方文档，找到允许加密所需的步骤。

作为开发人员，你需要了解在应用中使用数据库级加密的弱点。除其他外，我们可以强调以下几点：

+   特权数据库用户可以访问密钥环文件，因此在你的数据库中要严格控制用户权限。

+   数据在存储在服务器的 RAM 中时并不加密，只有在数据写入硬盘时才会加密。一个特权且恶意的用户可以使用一些工具来读取服务器内存，因此也可以读取你的应用数据。

+   一些工具，比如 GDB，可以用来更改根用户密码结构，从而允许你无任何问题地复制数据。

### MariaDB 中的加密

想象一下，如果你不想使用 Percona，而是想使用 MariaDB；由于`file_key_management`插件，数据库加密是可用的。在我们的应用示例中，我们正在使用 Percona 作为 secrets 微服务的数据存储，所以让我们添加一个新的 MariaDB 容器，以便以后尝试并交换这两个 RDBMS。

首先，在与数据库文件夹处于同一级别的 secrets 微服务内的 Docker 存储库中创建一个`mariadb`文件夹。在这里，你可以添加一个包含以下内容的`Dockerfile`：

```php
**FROM mariadb:latest

RUN apt-get update \
&& apt-get autoremove && apt-get autoclean \
&& rm -rf /var/lib/apt/lists/*

RUN mkdir -p /volumes/keys/
RUN echo 
"1;
C472621BA1708682BEDC9816D677A4FDC51456B78659F183555A9A895EAC9218" > 
/volumes/keys/keys.txt
RUN openssl enc -aes-256-cbc -md sha1 -k secret -in 
/volumes/keys/keys.txt -out /volumes/keys/keys.enc
COPY etc/ /etc/mysql/conf.d/**

```

在上述代码中，我们正在拉取最新的官方 MariaDB 镜像，更新它，并创建一些我们加密需要的证书。在`keys.txt`文件中保存的长字符串是我们自己生成的密钥，使用以下命令生成：

```php
**openssl enc -aes-256-ctr -k secret@phpmicroservices.com -P -md sha1**

```

我们`Dockerfile`的最后一个命令将我们定制的数据库配置复制到容器内。在`etc/encryption.cnf`中创建我们的自定义数据库配置，内容如下：

```php
    [mysqld]
    plugin-load-add=file_key_management.so
    file_key_management_filekey = FILE:/mount/keys/server-key.pem
    file-key-management-filename = /mount/keys/mysql.enc
    innodb-encrypt-tables = ON
    innodb-encrypt-log = 1
    innodb-encryption-threads=1
    encrypt-tmp-disk-tables=1
    encrypt-tmp-files=0
    encrypt-binlog=1
    file_key_management_encryption_algorithm = AES_CTR
```

在上述代码中，我们告诉我们的数据库引擎我们存储证书的位置，并启用了加密。现在，你可以编辑我们的`docker-compose.yml`文件，并添加以下容器定义：

```php
    microservice_secret_database_mariadb:
      build: ./microservices/secret/mariadb/
      environment:
        - MYSQL_ROOT_PASSWORD=mysecret
        - MYSQL_DATABASE=finding_secrets
        - MYSQL_USER=secret
        - MYSQL_PASSWORD=mysecret
      ports:
        - 7777:3306
```

从上述代码中可以看出，我们并没有定义任何新的内容；你现在可能已经有足够的 Docker 经验来理解我们正在定义`Dockerfile`的位置。我们设置了一些环境变量，并将本地的`7777`端口映射到容器的`3306`端口。一旦你做出所有的更改，一个简单的`docker-compose build microservice_secret_database`命令将生成新的容器。

构建完容器后，是时候检查一切是否正常运行了。使用`docker-compose up microservice_secret_database`启动新容器，并尝试将其连接到我们本地的`7777`端口。现在，你可以开始在这个容器中使用加密。考虑以下示例：

```php
    CREATE TABLE `test_encryption` (
      `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
      `text_field` varchar(255) NOT NULL,
      PRIMARY KEY (`id`)
    ) ENGINE=InnoDB `ENCRYPTED`=YES `ENCRYPTION_KEY_ID`=1;
```

在上述代码中，我们为我们的 SQL 添加了一些额外的标签；它们启用了表中的加密，并使用我们在`keys.txt`中存储的 ID 为`1`的加密密钥（我们用它来启动数据库的文件）。试一试，如果一切顺利，随时可以进行必要的更改，使用这个新的数据库容器代替我们项目中的另一个容器。

### InnoDB 加密

Percona 和 MySQL 5.7.11+版本自带一个新功能--支持**InnoDB**表空间级加密。有了这个功能，你可以在不需要太多麻烦或配置的情况下加密所有的 InnoDB 表。在我们的示例应用中，我们正在使用 Percona 5.7 来处理 secrets 微服务。让我们看看如何加密我们的表。

首先，我们需要对我们的 Docker 环境进行一些小的修改；首先，打开`microservices/secret/database/Dockerfile`，并用以下代码替换所有内容：

```php
    FROM percona:5.7
 **RUN mkdir -p /mount/mysql-keyring/ \**
 **&& touch /mount/mysql-keyring/keyring \**
 **&& chown -R mysql:mysql /mount/mysql-keyring**
**COPY etc/ /etc/mysql/conf.d/**

```

在本书的这一部分，你可能不需要解释我们在`Dockerfile`中做了什么，所以让我们创建一个新的`config`文件，稍后将其复制到我们的容器中。在`secret microservice`文件夹中，创建一个`etc`文件夹，并生成一个名为`encryption.cnf`的新文件，内容如下：

```php
    [mysqld]
    early-plugin-load=keyring_file.so
    keyring_file_data=/mount/mysql-keyring/keyring
```

在我们之前创建的配置文件中，我们正在加载`keyring`库，数据库可以在其中找到并存储用于加密数据的生成密钥环。

此时，您已经拥有了启用加密所需的一切，因此使用`docker-compose build microservice_secret_database`重新构建容器，并使用`docker-compose up -d`再次启动所有容器。

如果一切正常，您应该能够无问题地打开数据库，并且可以使用以下 SQL 命令更改我们存储的表：

```php
**ALTER TABLE `secrets` ENCRYPTION='Y'**

```

也许您会想知道为什么我们修改了`secrets`表，如果我们已经在数据库中启用了加密。背后的原因是因为加密不是默认启用的，因此您需要明确告诉引擎您想要加密哪些表。

### 性能开销

在数据库中使用加密将降低应用程序的性能。您的机器/容器将使用一些资源来处理加密/解密过程。在某些测试中，当您不使用表空间级加密（MySQL/Percona +5.7）时，这种开销可能超过 20%。我们建议您测量启用和未启用加密时应用程序的平均性能。这样，您可以确保加密不会对应用程序产生很大影响。

在本节中，我们向您展示了两种快速增加应用程序安全性的方法。使用这些功能的最终决定取决于您和您的应用程序的规格。

## TSL/SSL 协议

**传输层安全**（**TSL**）和**安全套接字层**（**SSL**）是用于在不受信任的网络中保护通信的加密协议，例如，互联网或 ISP 的局域网。 SSL 是 TSL 的前身，它们两者经常可以互换使用或与 TLS/SSL 一起使用。如今，SSL 和 TSL 实际上是一回事，如果您选择使用其中之一，选择另一个没有区别，您将使用服务器规定的相同级别的加密。例如，如果应用程序（例如电子邮件客户端）让您在 SSL 或 TSL 之间进行选择，您只是选择了安全连接的启动方式，没有其他区别。

这些协议的所有功能和安全性都依赖于我们所知的证书。TSL/SSL 证书可以定义为将加密密钥与组织或个人的详细信息数字绑定的小型数据文件。您可以找到各种公司出售 TSL/SSL 证书，但如果您不想花钱（或者您处于开发阶段），您可以创建自签名证书。这些类型的证书可用于加密数据，但客户端将不信任它们，除非您跳过验证。

### TSL/SSL 协议的工作原理

在您开始在应用程序中使用 TSL/SSL 之前，您需要了解它的工作原理。还有许多其他专门解释这些协议工作原理的书籍，因此我们只会给您一个初步了解。

以下图表总结了 TSL/SSL 协议的工作原理；首先，您需要知道 TSL/SSL 是一个 TCP 客户端-服务器协议，加密在经过几个步骤后开始：

![TSL/SSL 协议的工作原理](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_07_01.jpg)

TSL/SSL 协议

TSL/SSL 协议的步骤如下：

1.  我们的客户希望与使用 TSL/SSL 保护的服务器/服务建立连接，因此它要求服务器进行身份验证。

1.  服务器响应请求并向客户端发送其 TSL/SSL 证书的副本。

1.  客户端检查 TSL/SSL 证书是否是受信任的，如果是，则向服务器发送消息。

1.  服务器返回数字签名的确认以开始会话。

1.  在所有先前的步骤（握手）之后，加密数据在客户端和服务器之间共享。

正如你所能想象的，术语*客户端*和*服务器*是模棱两可的；客户端可以是试图访问你的页面的浏览器，也可以是试图与另一个微服务通信的微服务。

## TSL/SSL 终止

正如你之前学到的，为你的应用添加 TSL/SSL 层会给应用的整体性能增加一些开销。为了缓解这个问题，我们有所谓的 TSL/SSL 终止，一种 TSL/SSL 卸载形式，它将加密/解密的责任从服务器转移到应用的不同部分。

TSL/SSL 终止依赖于这样一个事实，即一旦所有数据被解密，你就信任你正在使用的所有通信渠道来传输这些解密后的数据。让我们以一个微服务为例；看一下下面的图片：

![TSL/SSL 终止](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_07_02.jpg)

微服务中的 TSL/SSL 终止

在上述图片中，所有的输入/输出通信都是使用我们微服务架构的特定组件加密的。这个组件将充当代理，并处理所有的 TSL/SSL 事务。一旦来自客户端的请求到来，它就会处理所有的握手并解密请求。一旦请求被解密，它就会被代理到特定的微服务组件（在我们的案例中，它是 NGINX），我们的微服务就会执行所需的操作，例如从数据库中获取一些数据。一旦微服务需要返回响应，它就会使用代理，其中我们所有的响应都是加密的。如果你有多个微服务，你可以扩展这个小例子并做同样的事情--加密不同微服务之间的所有通信，并在微服务内部使用加密数据。

## 使用 NGINX 进行 TSL/SSL

你可以找到多个软件，可以用来进行 TSL/SSL 终止。以下列出了一些最知名的：

+   **负载均衡器**：Amazon ELB 和 HaProxy

+   **代理**：NGINX、Traefik 和 Fabio

在我们的案例中，我们将使用 NGINX 来管理所有的 TSL/SSL 终止，但是请随意尝试其他选项。

你可能已经知道，NGINX 是市场上最多才多艺的软件之一。你可以将其用作反向代理或具有高性能水平和稳定性的 Web 服务器。

我们将解释如何在 NGINX 中进行 TSL/SSL 终止，例如对于 battle 微服务。首先，打开`microservices/battle/nginx/Dockerfile`文件，并在 CMD 命令之前添加以下命令：

```php
**RUN echo 01 > ca.srl \
&& openssl genrsa -out ca-key.pem 2048 \
&& openssl req -new -x509 -days 365 -subj "/CN=*" -key ca-key.pem -out ca.pem \
&& openssl genrsa -out server-key.pem 2048 \
&& openssl req -subj "/CN=*" -new -key server-key.pem -out server.csr \
&& openssl x509 -req -days 365 -in server.csr -CA ca.pem -CAkey ca-key.pem -out server-cert.pem \
&& openssl rsa -in server-key.pem -out server-key.pem \
&& cp *.pem /etc/nginx/ \
&& cp *.csr /etc/nginx/**

```

在这里，我们创建了一些自签名证书，并将它们存储在`nginx`容器的`/etc/nginx`文件夹中。

一旦我们有了证书，就是时候改变 NGINX 配置文件了。打开`microservices/battle/nginx/config/nginx/nginx.conf.ctmpl`文件，并添加以下服务器定义：

```php
    server {
      listen 443 ssl;
      server_name _;
      root /var/www/html/public;
      index index.php index.html;
      ssl on;
      ssl_certificate /etc/nginx/server-cert.pem;
      ssl_certificate_key /etc/nginx/server-key.pem;
      location = /favicon.ico { access_log off; log_not_found off; }
      location = /robots.txt { access_log off; log_not_found off; }
      access_log /var/log/nginx/access.log;
      error_log /var/log/nginx/error.log error;
      sendfile off;
      client_max_body_size 100m;
      location / {
        try_files $uri $uri/ /index.php?_url=$uri&$args;
      }
      location ~ /\.ht {
        deny all;
      }
      {{ if service $backend }}
      location ~ \.php$ {
        try_files $uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass {{ $backend }};
        fastcgi_index /index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME 
        $document_root$fastcgi_script_name;
        fastcgi_intercept_errors off;
        fastcgi_buffer_size 16k;
        fastcgi_buffers 4 16k;
      }
      {{ end }}
    }
```

上述代码片段在`nginx`服务器中设置了一个新的监听器，在`443`端口。正如你所看到的，它与默认服务器设置非常相似；不同之处在于端口和我们在上一步中创建的证书的位置。

为了使用这个新的 TSL/SSL 端点，我们需要对`docker-compose.yml`文件进行一些小的更改，并映射`443` NGINX 端口。你只需要去`microservice_battle_nginx`定义中添加一个新的端口声明行，如下所示：

```php
    - 8443:443
```

新的行将我们的`8443`端口映射到`nginx`容器的`443`端口，允许我们通过 TSL/SSL 连接。你现在可以用 Postman 试一试，但是由于它是一个自签名证书，默认情况下是不被接受的。打开**首选项**并禁用**SSL 证书验证**。作业时，你可以将我们所有的示例服务都改为只使用 TSL/SSL 层来相互通信。

在本章的这一部分，我们向您展示了如何为您的应用程序添加额外的安全层，加密数据和用于交换消息的通信渠道。现在我们确信我们的应用程序至少具有一定程度的加密，让我们继续讨论应用程序的另一个重要方面--认证。

# 认证

每个项目的起点是认证系统，通过它可以识别将使用我们的应用程序或 API 的用户或客户。有许多库可以实现不同的用户认证方式；在本书中，我们将看到两种最重要的方式：**OAuth 2**和**JWT**。

正如我们已经知道的，微服务是*无状态*的，这意味着它们应该使用*访问令牌*而不是 cookie 和会话与彼此和用户进行通信。因此，让我们看看使用它进行认证的工作流程是什么样的：

![认证](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_07_03-1.jpg)

通过令牌进行认证的工作流程

正如您在上图中所看到的，这应该是获取客户或用户所需的秘密列表的过程：

1.  **USER**向**FRONTEND LOGIN**请求秘密列表。

1.  **FRONTEND LOGIN**向**BACKEND**请求秘密列表。

1.  **BACKEND**向**FRONTEND LOGIN**请求用户访问令牌。

1.  **FRONTEND LOGIN**向**GOOGLE**（或任何其他提供者）请求访问令牌。

1.  **GOOGLE**向**USER**请求他们的凭据。

1.  **USER**向**GOOGLE**提供凭据。

1.  **GOOGLE**向**FRONTEND LOGIN**提供用户访问令牌。

1.  **FRONTEND LOGIN**提供**BACKEND**用户访问令牌。

1.  **BACKEND**与**GOOGLE**检查使用该访问令牌的用户是谁。

1.  **GOOGLE**告诉**BACKEND**用户是谁。

1.  **BACKEND**检查用户并告诉**FRONTEND LOGIN**秘密列表。

1.  **FRONTEND LOGIN**向**USER**显示秘密列表。

显然，在这个过程中，一切都是在用户不知情的情况下发生的。用户只需要向适当的服务提供他/她的凭据。在前面的例子中，服务是**GOOGLE**，但它甚至可以是我们自己的应用程序。

现在，我们将构建一个新的 docker 容器，以便使用 OAuth 2 和 JWT 来创建和设置一个用于认证用户的数据库。

在 docker 用户微服务的`docker/microservices/user/database/Dockerfile`数据库文件夹下创建一个`Dockerfile`，并添加以下行。我们将像我们为 secret 微服务所做的那样使用 Percona：

```php
    FROM percona:5.7
```

创建了`Dockerfile`之后，打开`docker-composer.yml`文件，并在用户微服务部分的末尾添加用户数据库微服务配置（就在源容器之前）。还要将`microservice_user_database`添加到`microservice_user_fpm`链接部分，以使数据库可见：

```php
    microservice_user_fpm:
    {{omitted code}}
    links:
    {{omitted code}}
 **- microservice_user_database**
 **microservice_user_database:**
 **build: ./microservices/user/database/**
 **environment:**
 **- CONSUL=autodiscovery**
 **- MYSQL_ROOT_PASSWORD=mysecret**
 **- MYSQL_DATABASE=finding_users**
 **- MYSQL_USER=secret**
 **- MYSQL_PASSWORD=mysecret**
 **ports:**
 **- 6667:3306**

```

一旦我们设置了配置，就该构建它了，所以在您的终端上运行以下命令来创建我们刚刚设置的新容器：

```php
**docker-compose build microservice_user_database**

```

这可能需要一些时间；当它完成时，我们必须通过运行以下命令再次启动容器：

```php
**docker-compose up -d**

```

您可以通过执行`docker ps`来检查用户数据库微服务是否正确创建，因此请检查其中的新`microservice_user_database`。

现在是时候设置用户微服务以便能够使用我们刚刚创建的数据库容器了，所以将以下行添加到`bootstrap/app.php`文件中：

```php
    $app->configure('database');
```

还要创建`config/database.php`文件，并添加以下配置：

```php
    <?php
      return [
        'default'     => 'mysql',
        'migrations'  => 'migrations',
        'fetch'       => PDO::FETCH_CLASS,
        'connections' => [
          'mysql' => [
            'driver'    => 'mysql',
            'host'      => env('DB_HOST','microservice_user_database'),
            'database'  => env('DB_DATABASE','finding_users'),
            'username'  => env('DB_USERNAME','secret'),
            'password'  => env('DB_PASSWORD','mysecret'),
            'collation' => 'utf8_unicode_ci',
          ]
        ]
      ];
```

请注意，在上述代码中，我们使用了与`docker-compose.yml`文件中用于连接到数据库容器的相同凭据。

就是这样。我们现在有一个新的数据库容器连接到用户微服务，它已经准备好使用了。通过创建迁移或在您喜爱的 SQL 客户端中执行以下查询来添加一个新的用户表：

```php
    CREATE TABLE `users` (
      `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
      `email` varchar(255) NOT NULL,
      `password` varchar(255) NOT NULL,
      `api_token` varchar(255) DEFAULT NULL,
      PRIMARY KEY (`id`)
    ) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=latin1;
```

## OAuth 2

让我们介绍一种安全且特别适用于微服务的基于访问令牌的认证系统。

OAuth 2 是一种标准协议，允许我们将 API REST 的某些方法限制为特定用户，而无需要求用户提供用户名和密码。

这个协议非常常见，因为它更安全，可以避免在 API 之间通信时共享密码或敏感凭据。

OAuth 2 使用访问令牌，用户需要获取该令牌才能使用应用程序。令牌将具有过期时间，并且可以在无需再次提供用户凭据的情况下进行刷新。

### 如何在 Lumen 上使用 OAuth 2

现在，我们将解释如何在 Lumen 上安装、设置和尝试 OAuth 2 身份验证。这样做的目的是让微服务使用 OAuth 2 来限制方法；换句话说，在使用需要身份验证的方法之前，消费者需要提供一个令牌。

#### OAuth 2 安装

通过在 docker 文件夹上执行以下命令进入用户微服务：

```php
**docker-compose up -d
docker exec -it  docker_microservice_user_fpm_1 /bin/bash**

```

一旦我们进入用户微服务，就需要通过在`composer.json`文件的`require`部分中添加以下行来安装 OAuth 2：

```php
    "lucadegasperi/oauth2-server-laravel": "⁵.0"
```

然后，执行`composer update`，该包将在您的微服务上安装 OAuth 2。

#### 设置

安装完包后，我们必须设置一些重要的东西才能运行 OAuth 2。首先，我们需要将位于`/vendor/lucadegasperi/oauth2-server-laravel/config/oauth2.php`的 OAuth 2 配置文件复制到`/config/oauth2.php`；如果`config`文件夹不存在，则创建它。此外，我们需要将包含在`/vendor/lucadegasperi/oauth2-server-laravel/database/migrations`中的迁移文件复制到`/database/migrations`文件夹中。

不要忘记通过在`/bootstrap/app.php`中添加以下行来注册 OAuth 2：

```php
    $app-
    >register(\LucaDegasperi\OAuth2Server\Storage\
    FluentStorageServiceProvider::class);
    $app-    >register(\LucaDegasperi\OAuth2Server\
    OAuth2ServerServiceProvider::class);
    $app->middleware([
      \LucaDegasperi\OAuth2Server\Middleware\
      OAuthExceptionHandlerMiddleware::class
    ]);
```

在`app->withFacades();`行之前的文件顶部（如果没有取消注释，请这样做），添加以下行：

```php
    class_alias('Illuminate\Support\Facades\Config', 'Config');
    class_alias(\LucaDegasperi\OAuth2Server\Facades\Authorizer::class, 
    'Authorizer');
```

现在，我们将执行迁移以在数据库中创建必要的表：

```php
**composer dumpautoload
php artisan migrate**

```

### 提示

如果在执行迁移时遇到问题，请尝试将`'migrations' => 'migrations', 'fetch' => PDO::FETCH_CLASS,`添加到`config/database.php`文件中，然后执行`php artisan migrate:install --database=mysql`。

一旦我们创建了所有必要的表，可以使用 Lumen seeders 在`oauth_clients`表中插入一个注册，或者通过在您喜爱的 SQL 客户端上执行以下查询来执行：

```php
    INSERT INTO `finding_users`.`oauth_clients`
    (`id`, `secret`, `name`, `created_at`, `updated_at`)
    VALUES
    ('1', 'YouAreTheBestDeveloper007', 'PHPMICROSERVICES', NULL, NULL);
```

现在，我们必须在`/app/Http/routes.php`中添加一个新路由，以便为我们刚刚创建的用户获取有效的令牌。例如，路由可以是`oauth/access_token`：

```php
    $app->post('**oauth/access_token**', function() {
      return response()->json(Authorizer::issueAccessToken());
    });
```

最后，修改`/config/oauth2.php`文件中的`grant_types`值，将其更改为以下代码行：

```php
    'grant_types' => [
      'client_credentials' => [
        'class'            => '\League\OAuth2\Server\Grant\
        ClientCredentialsGrant',
        'access_token_ttl' => 0
      ]
    ],
```

#### 让我们尝试 OAuth2

现在，我们可以通过在 Postman 上对`http://localhost:8084/api/v1/oauth/access_token`进行 POST 调用来获取我们的令牌，包括在 body 中包含以下参数：

```php
 **grant_type:** client_credentials
 **client_id:** 1
 **client_secret:** YouAreTheBestDeveloper007
```

如果输入错误的凭据，将会得到以下响应：

```php
    {
      "error": "invalid_client",
      "error_description": "Client authentication failed."
    }
```

如果凭据正确，我们将在 JSON 中获得`access_token`：

```php
    {
      "access_token": "**anU2e6xgXiLm7UARSSV7M4Wa7u86k4JryKWrIQhu**",
      "token_type": "Bearer",
      "expires_in": 3600
    }
```

一旦我们获得有效的访问令牌，我们可以限制一些未注册用户的方法。这在 Lumen 上非常容易。我们只需在`/bootstrap/app.php`上启用路由中间件，因此在该文件中添加以下代码：

```php
    $app->routeMiddleware(
      [
        'check-authorization-params' => 
        \LucaDegasperi\OAuth2Server\Middleware\
        CheckAuthCodeRequestMiddleware::class,
        'csrf' => \Laravel\Lumen\Http\Middleware\
        VerifyCsrfToken::class,
        'oauth' => 
        \LucaDegasperi\OAuth2Server\Middleware\
        OAuthMiddleware::class,
        'oauth-client' => \LucaDegasperi\OAuth2Server\Middleware\
        OAuthClientOwnerMiddleware::class,
        'oauth-user' => \LucaDegasperi\OAuth2Server\Middleware\
        OAuthUserOwnerMiddleware::class,
      ]
    );
```

转到`UserController.php`文件并添加一个带有以下代码的`__construct()`函数：

```php
    public function __construct(){
      $this->middleware('oauth');
    }
```

这将影响控制器上的所有方法，但我们可以使用以下代码排除其中一些方法：

```php
    public function __construct(){
      $this->middleware('oauth', **['except' => 'index']**);
    }
    public function index()
    {
      return response()->json(['method' => 'index']);
    }
```

现在，我们可以通过在`http://localhost:8084/api/v1/user`上进行 GET 调用来测试 index 函数。不要忘记在`Authorization`标头中包含`Bearer anU2e6xgXiLm7UARSSV7M4Wa7u86k4JryKWrIQhu`值。

如果我们排除了 index 函数，或者如果我们正确输入了令牌，我们将获得状态码 200 的 JSON 响应：

```php
    {"method":"index"}
```

如果我们没有排除 index 方法并输入了错误的令牌，我们将收到错误代码 401 和以下消息：

```php
    {"error":"access_denied","error_description":"The resource owner or 
    authorization server denied the request."}
```

现在您有一个安全且更好的应用程序。请记住，您可以将上一章中学到的错误处理添加到您的授权方法中。

## JSON Web Token

**JSON Web Token**（**JWT**）是一组安全方法，用于 HTTP 请求和客户端与服务器之间的传输。JWT 令牌是使用 JSON Web 签名进行数字签名的 JSON 对象。

为了使用 JWT 创建令牌，我们需要用户凭据、秘密密钥和要使用的加密类型；可以是 HS256、HS384 或 HS512。

### 如何在 Lumen 上使用 JWT

可以使用 composer 在 Lumen 上安装 JWT。因此，一旦您在用户微服务容器中，就在终端中执行以下命令：

```php
**composer require tymon/jwt-auth:"¹.0@dev"**

```

安装该库的另一种方法是打开您的`composer.json`文件，并将`"tymon/jwt-auth": "¹.0@dev"`添加到所需库列表中。安装后，我们需要像在 OAuth 2 中注册服务提供程序一样在注册服务提供程序上注册 JWT。在 Lumen 上，可以通过在`bootstrap/app.php`文件中添加以下行来实现：

```php
    $app->register('Tymon\JWTAuth\Providers\JWTAuthServiceProvider');
```

还要取消以下行的注释：

```php
    $app->register(App\Providers\AuthServiceProvider::class);
```

您的`bootstrap/app.php`文件应如下所示：

```php
    <?php
      require_once __DIR__.'/../vendor/autoload.php';
      try {
        (new Dotenv\Dotenv(__DIR__.'/../'))->load();
      } catch (Dotenv\Exception\InvalidPathException $e) {
        //
      }
      $app = new Laravel\Lumen\Application(
        realpath(__DIR__.'/../')
      );
      // $app->withFacades();
 **$app->withEloquent();**
      $app->singleton(
        Illuminate\Contracts\Debug\ExceptionHandler::class,
        App\Exceptions\Handler::class
      );
      $app->singleton(
        Illuminate\Contracts\Console\Kernel::class,
        App\Console\Kernel::class
      );
 **$app->routeMiddleware([**
 **'auth' => App\Http\Middleware\Authenticate::class,**
 **]);**
      $app->register(App\Providers\AuthServiceProvider::class);
 **$app->register
      (Tymon\JWTAuth\Providers\LumenServiceProvider::class);**
      $app->group(['namespace' => 'App\Http\Controllers'], 
      function ($app) 
      {
           require __DIR__.'/../app/Http/routes.php';
      });
      return $app;
```

#### 设置 JWT

现在我们需要一个秘密密钥，因此运行以下命令以生成并将其放置在 JWT 配置文件中：

```php
**php artisan jwt:secret**

```

生成后，您可以在`.env`文件中看到放置的秘密密钥（您的秘密密钥将不同）。检查并确保您的`.env`如下所示：

```php
    APP_DEBUG=true
    APP_ENV=local
    SESSION_DRIVER=file
    DB_HOST=microservice_user_database
    DB_DATABASE=finding_users
    DB_USERNAME=secret
    DB_PASSWORD=mysecret
 **JWT_SECRET=wPB1mQ6ADZrc0ouxMCYJfiBbMC14IAV0**
    CACHE_DRIVER=file
```

现在，转到`config/jwt.php`文件；这是 JWT `config`文件，请确保您的文件如下所示：

```php
    <?php
      return [
        'secret' => env('JWT_SECRET'),
        'keys' => [
          'public' => env('JWT_PUBLIC_KEY'),
          'private' => env('JWT_PRIVATE_KEY'),
          'passphrase' => env('JWT_PASSPHRASE'),
        ],
        'ttl' => env('JWT_TTL', 60),
        'refresh_ttl' => env('JWT_REFRESH_TTL', 20160),
        'algo' => env('JWT_ALGO', 'HS256'),
        'required_claims' => ['iss', 'iat', 'exp', 'nbf', 'sub', 
        'jti'],
        'blacklist_enabled' => env('JWT_BLACKLIST_ENABLED', true),
        'blacklist_grace_period' => env('JWT_BLACKLIST_GRACE_PERIOD', 
        0),
        'providers' => [
          'jwt' => Tymon\JWTAuth\Providers\JWT\Namshi::class,
          'auth' => Tymon\JWTAuth\Providers\Auth\Illuminate::class,
          'storage' => 
          Tymon\JWTAuth\Providers\Storage\Illuminate::class,
        ],
      ];
```

还需要正确设置`config/app.php`。确保您正确输入了用户模型，它将定义 JWT 应该搜索用户和提供的密码的表：

```php
    <?php
      return [
        'defaults' => [
          'guard' => env('AUTH_GUARD', 'api'),
          'passwords' => 'users',
        ],
        'guards' => [
          'api' => [
            'driver' => 'jwt',
            'provider' => 'users',
          ],
        ],
        'providers' => [
          'users' => [
            'driver' => 'eloquent',
 **'model' => \App\Model\User::class,**
          ],
        ],
        'passwords' => [
          'users' => [
            'provider' => 'users',
            'table' => 'password_resets',
            'expire' => 60,
          ],
        ],
      ];
```

现在，我们准备通过编辑`/app/Http/routes.php`来定义需要身份验证的方法：

```php
    <?php
      $app->get('/', function () use ($app) {
        return $app->version();
      });
      use Illuminate\Http\Request;
      use Tymon\JWTAuth\JWTAuth;
      $app->post('login', function(Request $request, JWTAuth $jwt) {
        $this->validate($request, [
          'email' => 'required|email|exists:users',
          'password' => 'required|string'
        ]);
        if (! $token = $jwt->attempt($request->only(['email', 
        'password']))) {
          return response()->json(['user_not_found'], 404);
        }
        return response()->json(compact('token'));
      });
      $app->group(**['middleware' => 'auth']**, function () use ($app) {
        $app->post('user', function (JWTAuth $jwt) {
          $user = $jwt->parseToken()->toUser();
          return $user;
        });
      });
```

您可以在上述代码中看到，我们的中间件只影响我们在其中定义了中间件的组中包含的方法。我们可以创建所有我们想要的组，以便通过我们选择的中间件传递方法。

最后，编辑`/app/Providers/AuthServiceProvider.php`文件，并添加以下突出显示的代码：

```php
    <?php
      namespace App\Providers;
      use App\User;
      use Illuminate\Support\ServiceProvider;
      class AuthServiceProvider extends ServiceProvider
      {
        public function register()
        {
          //
        }
        public function boot()
        {
 **$this->app['auth']->viaRequest('api', function ($request) {**
 **if ($request->input('email')) {**
 **return User::where('email', $request->input('email'))-
              >first();**
 **}**
 **});**
        }
      }
```

最后，我们需要对用户模型文件进行一些更改，因此转到`/app/Model/User.php`并将以下行添加到类实现列表中的`JWTSubject`：

```php
    <?php
      namespace App\Model;
      use Illuminate\Contracts\Auth\Access\Authorizable as 
      AuthorizableContract;
      use Illuminate\Database\Eloquent\Model;
      use Illuminate\Auth\Authenticatable;
      use Laravel\Lumen\Auth\Authorizable;
      use Illuminate\Contracts\Auth\Authenticatable as 
      AuthenticatableContract;
 **use Tymon\JWTAuth\Contracts\JWTSubject;**
      class User extends Model implements **JWTSubject**, 
      AuthorizableContract, 
      AuthenticatableContract {
        use Authenticatable, Authorizable;
        protected $table = 'users';
        protected $fillable = ['email', 'api_token'];
        protected $hidden = ['password'];
   **public function getJWTIdentifier()**
 **{**
 **return $this->getKey();**
 **}**
 **public function getJWTCustomClaims()**
 **{**
 **return [];**
 **}**
      }
```

不要忘记添加`getJWTIdentifier()`和`getJWTCustomClaims()`函数，如上述代码所示。这些函数是实现`JWTSubject`所必需的。

#### 让我们尝试 JWT

为了测试这一点，我们必须在数据库的用户表中创建一个新用户。因此，通过执行迁移或在您喜欢的 SQL 客户端中执行以下查询来添加它：

```php
    INSERT INTO `finding_users`.`users`
    (`id`, `email`, `password`, `api_token`)
    VALUES
    (1,'john@phpmicroservices.com',
    '$2y$10$m5339OpNKEh5bL6Erbu9r..sjhaf2jDAT2nYueUqxnsR752g9xEFy',
    NULL,);
```

手动插入的哈希密码对应于'123456'。Lumen 会为安全原因保存您的用户密码的哈希值。

打开 Postman 并尝试通过对`http://localhost:8084/user`进行 POST 调用。您应该收到以下响应：

```php
    Unauthorized.
```

这是因为`http://localhost:8084/user`方法受到身份验证中间件的保护。您可以在`routes.php`文件中检查这一点。为了获取用户，需要提供有效的访问令牌。

获取有效访问令牌的方法是`http://localhost:8084/login`，因此使用与我们添加的用户对应的参数进行 POST 调用，`email = john@phpmicroservices.com`，密码为`123456`。如果它们是正确的，我们将获得有效的访问令牌：

```php
    {"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.
    eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODQvbG9naW4iLCJ
    pYXQiOjE0ODA4ODI4NTMsImV4cCI6MTQ4MDg4NjQ1MywibmJmIjox
    NDgwODgyODUzLCJqdGkiOiJVVnRpTExZTFRWcEtyWnhsIiwic3
    ViIjoxfQ.jjgZO_Lf4dlfwYiOYAOhzvcTQ4EGxJUTgRSPyMXJ1wg"}
```

现在，我们可以使用前面的访问令牌进行 POST 调用`http://localhost:8084/user`，就像以前一样。这次，我们将获得用户信息：

```php
    {"id":1,"email":"john@phpmicroservices.com","api_token":null}
```

如您所见，使用有效的访问令牌保护您的方法非常简单。这将使您的应用程序更加安全。

# 访问控制列表

这是所有应用程序中非常常见的系统，无论其大小如何。**访问控制列表**（**ACL**）为我们提供了一种简单的方式来管理和过滤每个用户的权限。让我们更详细地看一下。

## ACL 是什么？

应用程序用于识别应用程序的每个单个用户的方法是 ACL。这是一个系统，它告诉应用程序特定任务或操作的用户或用户组有什么访问权限或权限。

每个任务（函数或操作）都有一个属性来标识哪些用户可以使用它，ACL 是一个将每个任务与每个操作（如读取、写入或执行）关联的列表。

对于使用 ACL 的应用程序，ACL 具有以下两个特点优势：

+   **管理**：在我们的应用程序中使用 ACL 允许我们将用户添加到组中，并管理每个组的权限。此外，可以更容易地向许多用户或组添加、修改或删除权限。

+   **安全性**：为每个用户设置不同的权限对应用程序的安全性更好。它可以避免虚假用户或利用通过给予普通用户和管理员不同的权限来破坏应用程序。

对于我们基于微服务的应用程序，我们建议为每个微服务设置不同的 ACL；这样可以避免整个应用程序只有一个入口点。请记住，我们正在构建微服务，其中一个要求是微服务应该是隔离和独立的；因此，有一个微服务来控制其他微服务并不是一个好的做法。

这并不是一项困难的任务，这是有道理的，因为每个微服务应该有不同的任务，每个任务在权限方面对每个用户都是不同的。想象一下，我们有一个用户，该用户具有以下权限。该用户可以创建秘密并检查附近的秘密，但不允许创建战斗或新用户。在全局管理 ACL 将成为一个问题，因为当新的微服务添加到系统中时，甚至当新的开发人员加入团队并且他们必须理解全局 ACL 的复杂系统时，会出现可扩展性问题。正如你所看到的，最好为每个微服务设置一个 ACL 系统，这样当你添加一个新的微服务时，就不需要修改其余的 ACL。

## 如何使用 ACL

Lumen 为我们提供了一个身份验证过程，以便让用户注册、登录、注销和重置密码，并且还提供了一个名为`Gate`的 ACL 系统。

`Gate`允许我们知道特定用户是否有权限执行特定操作。这非常简单，可以在 API 的每个方法中使用。

要在 Lumen 上设置 ACL，必须通过从`app->withFacades();`行中删除分号来启用门面；如果您的文件中没有这一行，请添加它。

在`config/Auth.php`上创建一个新文件是必要的，文件中包含以下代码：

```php
    <?php
      return [
        'defaults' => [
          'guard' => env('AUTH_GUARD', 'api'),
        ],
        'guards' => [
          'api' => [
            'driver' => 'token',
            'provider' => 'users'
          ],
        ],
        'providers' => [
          'users' => [
            'driver' => 'eloquent',
            // We should get model name from JWT configuration
            'model' => app('config')->get('jwt.user'),
          ],
        ],
      ];
```

在我们的控制器上使用`Gate`类来检查用户权限，需要上述代码。

设置好这些后，我们必须定义特定用户可用的不同操作或情况。为此，打开`app/Providers/AuthServiceProvider.php`文件；在`boot()`函数中，我们可以通过编写以下代码来定义每个操作或情况：

```php
    <?php
      /* Code Omitted */
      use Illuminate\Contracts\Auth\Access\Gate;
      class AuthServiceProvider extends ServiceProvider
      {
        /* Code Omitted */
        public function boot()
        {
          Gate::define('update-profile', function ($user, $profile) {
            return $user->id === $profile->user_id;
          });
        }
```

一旦我们定义了情况，我们就可以将其放入我们的函数中。有三种不同的使用方法：*allows*、*checks*和*denies*。前两种是相同的，当定义的情况返回 true 时，它们返回 true，最后一种在定义的情况返回 false 时返回 true：

```php
    if (Gate::**allows**('update-profile', $profile)) {
      // The current user can update their profile...
    }
    if (Gate::**denies**('update-profile', $profile)) {
      // The current user can't update their profile...
    }
```

正如你所看到的，不需要发送`$user`变量，它会自动获取当前用户。

# 源代码的安全性

最有可能的情况是，您的项目将使用一些凭证连接到外部服务，例如数据库。您会把所有这些信息存储在哪里？最常见的方法是在源代码中有一个配置文件，您可以在其中放置所有凭证。这种方法的主要问题是您会提交凭证，任何有权访问源代码的人都将能够访问它们。不管您信任有权访问存储库的人，将凭证存储起来都不是一个好主意。

如果您不能在源代码中存储凭证，您可能想知道如何存储它们。您有两个主要选项：

+   环境变量

+   外部服务

让我们来看看每一个，这样您就可以选择哪个选项更适合您的项目。

## 环境变量

这种存储凭证的方式非常容易实现--您只需定义要存储在环境中的变量，稍后可以在源代码中获取它们。

我们选择的项目框架是 Lumen，使用这个框架非常容易定义您的环境变量，然后在代码中使用它们。最重要的文件是位于源代码根目录的`.env`文件。默认情况下，这个文件在`gitignore`中，以避免被提交，但框架附带了一个`.env.example`示例，以便您可以查看如何定义这些变量。在这个文件中，您可以找到以下定义：

```php
    DB_CONNECTION=mysql
    DB_HOST=localhost
    DB_PORT=3306
    DB_DATABASE=homestead
    DB_USERNAME=homestead
    DB_PASSWORD=secret
```

前面的定义将创建环境变量，您可以使用简单的`env('DB_DATABASE');`或`env('DB_DATABASE', 'default_value');`在代码中获取值。`env()`函数支持两个参数，因此您可以定义一个默认值，以防您要获取的变量未定义。

使用环境变量的主要好处是您可以拥有不同的环境，而无需更改源代码中的任何内容；您甚至可以在不对代码进行任何更改的情况下更改值。

## 外部服务

这种存储凭证的方式使用外部服务来存储所有凭证，它们的工作方式与环境变量差不多。当您需要任何凭证时，您必须向该服务请求。

这些天主流的凭证存储系统之一是 HashiCorp Vault 项目，这是一个开源工具，允许您创建一个安全的地方来存储您的凭证。它有多个好处，我们其中一些重点包括以下几点：

+   HTTP API

+   密钥滚动

+   审计日志

+   支持多个秘密后端

使用外部服务的主要缺点是您为应用程序增加了额外的复杂性；您将添加一个新组件来管理和保持最新状态。

# 跟踪和监控

当您处理应用程序中的安全性时，重要的是要跟踪和监视其中发生的事情。在第六章 *监控*中，我们实现了 Sentry 作为日志和监控系统，并且还添加了 Datadog 作为我们的 APM，因此您可以使用这些工具来跟踪发生的情况并发送警报。

然而，您想要跟踪什么？让我们想象一下，您有一个登录系统，这个组件是一个很好的地方来添加您的跟踪。如果您跟踪每次用户登录失败，您就可以知道是否有人试图攻击您的登录系统。

您的应用程序是否允许用户添加、修改和删除内容？跟踪内容的任何更改，以便您可以检测到不受信任的用户。

在安全方面，没有关于要跟踪什么和不要跟踪什么的标准，只需运用常识。我们的主要建议是创建一个敏感点列表，至少涵盖用户可以登录、创建内容或删除内容的地方，并将这些列表用作添加跟踪和监控的起点。

# 最佳实践

与应用程序的任何其他部分一样，当您处理安全性时，有一些众所周知的最佳实践需要遵循，或者至少要意识到以避免未来的问题。在这里，您可以找到与 Web 开发相关的最常见的最佳实践。

## 文件权限和所有权

文件/文件夹权限和所有权是最基本的安全机制之一。假设您正在使用 Linux/Unix 系统，主要建议是将您的源代码的所有权分配给 Web 服务器或 PHP 引擎用户。关于文件权限，您应该使用以下设置：

+   目录的 500 权限（dr-x------）：此设置防止意外删除或修改目录中的文件。

+   文件的 400 权限（-r--------）：此设置防止任何用户覆盖文件。

+   700 权限（drwx------）：这适用于任何可写目录。它给予所有者完全控制，并用于上传文件夹。

+   600 权限（-rw-------）：这个设置适用于任何可写文件。它避免了任何非所有者的用户对您的文件进行修改。

## PHP 执行位置

通过仅允许在选定路径上执行 PHP 脚本并拒绝在敏感（可写）目录中执行任何类型的执行，例如，任何上传目录，避免任何未来问题。

## 永远不要相信用户

作为一个经验法则，永远不要相信用户。过滤来自任何人的任何输入，您永远不知道表单提交背后的黑暗意图。当然，永远不要仅依赖于前端过滤和验证。如果您在前端添加了过滤和验证，请在后端再次进行过滤和验证。

## SQL 注入

没有人希望他们的数据被暴露或被未经许可的人访问，对您的应用程序的这种攻击是由于输入的过滤或验证不当。想象一下，您使用一个字段来存储未经正确过滤的用户名称，恶意用户可以使用此字段执行 SQL 查询。为了帮助您避免这个问题，当您处理数据库时，请使用 ORM 过滤方法或您喜欢的框架中可用的任何过滤方法。

## 跨站脚本 XSS

这是对您的应用程序的另一种攻击类型，是由于过滤不当。如果您允许用户在页面上发布任何类型的内容，一些恶意用户可能会未经您的许可向页面添加脚本。想象一下，您的页面上有评论部分，您的输入过滤不是最好的，恶意用户可以添加一个作为评论的脚本，打开垃圾邮件弹出窗口。记住我们之前告诉过您的--永远不要相信您的用户--过滤和验证一切。

## 会话劫持

在这种攻击中，恶意用户窃取另一个用户的会话密钥，使恶意用户有机会像其他用户一样。想象一下，您的应用程序涉及财务信息，一个恶意用户可以窃取管理员会话密钥，现在这个用户可以获得他们需要的所有信息。大多数情况下，会话是通过 XSS 攻击窃取的，所以首先要尽量避免任何 XSS 攻击。另一种减轻这个问题的方法是防止 JavaScript 访问会话 ID；您可以在`php.ini`中使用`session.cookie.httponly`设置来做到这一点。

## 远程文件

从您的应用程序包含远程文件可能非常危险，您永远无法 100%确定您包含的远程文件是否可信。如果在某个时刻，被包含的远程文件受到损害，攻击者可以为所欲为，例如，从您的应用程序中删除所有数据。

避免这种问题的简单方法是在您的`php.ini`中禁用远程文件。打开它并禁用以下设置：

+   `allow_url_fopen`：默认情况下启用

+   `allow_url_include`：默认情况下禁用；如果禁用`allow_url_fopen`设置，它会强制禁用此设置。

## 密码存储

永远不要以明文存储任何密码。当我们说永远不要，我们是指永远不要。如果你认为你需要检查用户的密码，那么你是错误的，任何恢复或补充丢失密码的操作都需要通过恢复系统进行。当你存储一个密码时，你存储的是与一些随机盐混合的密码哈希。

## 密码策略

如果你保留敏感数据，并且不希望你的应用程序因用户的密码而暴露，那么请制定非常严格的密码策略。例如，你可以创建以下密码策略来减少破解和字典攻击：

+   至少 18 个字符

+   至少 1 个大写字母

+   至少 1 个数字

+   至少 1 个特殊字符

+   以前未使用过

+   不是用户数据的串联，将元音变成数字

+   每 3 个月过期

## 源代码泄露

将源代码放在好奇的眼睛看不见的地方，如果你的服务器出了问题，所有的源代码都将以明文形式暴露出来。避免这种情况的唯一方法是只在 web 服务器根目录中保留所需的文件。另外，要小心特殊文件，比如`composer.json`。如果我们暴露了我们的`composer.json`，每个人都会知道我们每个库的不同版本，从而轻松地了解可能存在的任何错误。

## 目录遍历

这种攻击试图访问存储在 web 根目录之外的文件。大多数情况下，这是由于代码中的错误导致的，因此恶意用户可以操纵引用文件的变量。没有简单的方法可以避免这种情况；然而，如果你使用外部框架或库，保持它们最新将有所帮助。

这些是你需要注意的最明显的安全问题，但这并不是一个详尽的列表。订阅安全新闻通讯，并保持所有代码最新，以将风险降到最低。

# 总结

在这一章中，我们谈到了安全和认证。我们向您展示了如何加密数据和通信层；我们甚至向您展示了如何构建一个强大的登录系统，以及如何处理应用程序的秘密。安全是任何项目中非常重要的一个方面，所以我们给出了一个常见安全风险的小列表，当然，主要建议是——永远不要相信你的用户。


# 第八章：部署

在前几章中，您已经学会了如何基于微服务开发应用程序。现在，是时候学习如何部署您的应用程序，学习最佳的自动化策略和回滚应用程序的方法，以及在需要时进行备份和恢复。

# 依赖管理

正如我们在第五章中提到的，*微服务开发*，**Composer**是最常用的依赖管理工具；它可以帮助我们在部署过程中将项目从开发环境移动到生产环境。

关于部署过程的最佳工作流有不同的观点，因此让我们看一下每种情况的优缺点。

## Composer require-dev

Composer 在他们的`composer.json`中提供了一个名为`require-dev`的部分，用于在开发环境中使用，并且当我们需要在应用程序中安装一些不需要在生产环境中的库时，我们必须使用它。

正如我们已经知道的，使用 Composer 安装新库的命令是`composer require library-name`，但如果我们想安装新的库，比如测试库、调试库或者其他在生产环境下没有意义的库，我们可以使用`composer require-dev library-name`。它会将库添加到`require-dev`部分，当我们将项目部署到生产环境时，我们应该在执行`composer install --no-dev`或`composer update --no-dev`时使用`--no-dev`参数，以避免安装开发库。

## .gitignore 文件

通过`.gitignore`文件，可以忽略您不想跟踪的文件或文件夹。尽管 Git 是一个版本控制工具，但许多开发人员在部署过程中使用它。`.gitignore`文件包含一系列在更改时不会在存储库中跟踪的文件和文件夹。这通常用于上传包含用户上传的图像或其他文件的文件夹，也用于 vendor 文件夹，该文件夹包含项目中使用的所有库。

## Vendor 文件夹

`vendor`文件夹包含我们应用程序中使用的所有库。如前所述，关于如何使用`vendor`文件夹有两种不同的思考方式。在生产中包含 Composer 以便在应用程序部署后从存储库获取`vendor`文件夹，或者在生产中将开发中使用的库下载到生产中。

## 部署工作流

部署工作流可能因项目需求而异。例如，如果您想在存储库中保留整个项目，包括`vendor`文件夹，或者如果您希望在项目部署后从 Composer 获取库。在本章中，我们将看一下一些最常见的工作流。

### 存储库中的 Vendor 文件夹

第一个部署工作流在存储库中有整个应用程序。这是当我们在开发环境中第一次使用 Composer 并将`vendor`文件夹推送到我们的存储库时，所有的库都将保存在存储库中。

因此，在生产中，我们将从存储库中获取整个项目，而无需进行 Composer 更新，因为我们的库已经在部署中投入生产。因此，在生产中不需要 Composer。

在存储库中包含**`vendor`**文件夹的优点如下：

+   您知道相同的代码（包括库）在开发中是可以工作的。

+   在生产中更新库的风险较小。

+   在部署过程中，您不依赖外部服务。有时，库在特定时刻不可用。

在存储库中包含**`vendor`**文件夹的缺点如下：

+   你的存储库必须存储已经存储在 Composer 上的库。如果你需要许多或大型库，所需的空间可能会成为一个问题。

+   你正在存储不属于你的代码。

### 生产环境中的 Composer

第二个部署工作流程有两种不同的进行方式，但它们都不需要将`vendor`文件夹存储在存储库中；一旦代码部署到生产环境，它们将从 Composer 获取库。

一旦代码部署到生产环境，将会执行`composer update`命令，可以是**手动**或**自动**在部署过程中执行。

在生产环境中运行 Composer 的优点如下：

+   你可以在你的存储库中节省空间

+   你可以在生产环境中执行–optimize-autoload 以映射添加的库

在生产环境中运行 Composer 的缺点如下：

+   部署过程将取决于外部服务。

+   在更新包时，某些情况下存在重大风险。例如，如果一个库突然被修改或损坏，你的应用程序将会崩溃。

## 前端依赖关系

需要知道在前端也可以管理依赖关系，因此可以选择是将其放在存储库中还是不放。Grunt 和 Gulp 是两种最常用的工具，用于自动化应用程序中的任务。此外，如果基于微服务的应用程序有前端部分，你应该使用以下工具来管理样式和资产。

### Grunt

**Grunt**是一个用于自动化应用程序任务的工具。Grunt 可以帮助你合并或压缩 JS 和 CSS 文件，优化图像，甚至帮助你进行单元测试。

每个任务都是由 JavaScript 开发的 Grunt 插件实现的。它们也使用 Node.js，因此使 Grunt 成为一种多平台工具。你可以在 [`gruntjs.com/plugins`](http://gruntjs.com/plugins) 上查看所有可用的插件。

学习 Node.js 并不是必要的，只需安装 Node.js，你就可以安装 Grunt（以及许多其他包）所需的 Node Packaged Modules。一旦安装了 Node.js，运行以下命令：

```php
**npm install grunt-cli -g**

```

现在，你可以创建一个`package.json`，它将被 NPM 命令读取：

```php
    {
      "name": "finding-secrets",
      "version": "0.1.0",
      "devDependencies": {
        "grunt": "~0.4.1"
      }
    }
```

然后，`npm install`将安装`package.json`文件中包含的依赖项。Grunt 将存储在`node_modules`文件夹中。一旦安装了 Grunt，就需要创建一个`Gruntfile.js`来定义自动化任务，如下面的代码所示：

```php
    'use strict';
    module.exports = function (grunt) {
    grunt.**initConfig**({
      pkg: grunt.file.readJSON('package.json'),
    });
    //grunt.**loadNpmTasks**('grunt-contrib-xxxx');
    //grunt.**registerTask**('default', ['xxxx']);
    };
```

有三个部分来定义自动化任务：

+   **InitConfig**：这是指由 Grunt 执行的任务

+   **LoadNpmTask**：这用于加载所需的插件以执行任务

+   **RegisterTask**：这注册将运行的任务

一旦决定安装哪个插件并定义所有必要的任务，就在终端上运行 grunt 来执行它们。

### Gulp

与 Grunt 一样，**Gulp**也是一个用于自动化任务的工具，它也是基于 NodeJS 开发的，因此需要安装 Node.js 才能安装 NPM。一旦安装了 Node.js，就可以通过运行以下命令全局安装 Gulp：

```php
**npm install -g gulp**

```

另一种安装 gulp 的方式，也是推荐的选项，是本地安装，你可以使用以下命令来完成：

```php
**npm install --save-dev gulp**

```

所有任务都应该包含在位于根项目上的`gulpfile.js`中以进行自动化：

```php
    var gulp = require('gulp');
    gulp.task('default', function () {
    });
```

上述代码非常简单。正如你所看到的，代码是`gulp.task`，任务名称，然后是为该任务名称定义的`function`。

一旦你定义了函数，你就可以运行`gulp`。

### SASS

CSS 很复杂，庞大，难以维护。你能想象维护一个有成千上万行的文件吗？这就是 Sass 可以发挥作用的地方。这是一个预处理器，为 CSS 添加了变量、嵌套、混合、继承等功能，使 CSS 成为一种真正的开发语言。

**Syntactically Awesome Stylesheets** (**SASS**)是 CSS 的元语言。它是一种被翻译成 CSS 的脚本语言。SassScript 是 Sass 语言，它有两种不同的语法：

+   **缩进语法:** 这使用缩进来分隔块代码，换行符来分隔规则

+   **SCSS**: 这是 CSS 语法的扩展，它使用大括号来分隔代码块，分号来分隔块内的行

缩进的语法有`.sass`扩展名，SCSS 有`.scss`扩展名。

Sass 非常简单易用。一旦安装，只需在终端上运行`sass input.scss output.css`。

### Bower

**Bower**是一个类似 Composer 的依赖管理工具，但它适用于前端。它也基于 Node.js，因此一旦安装了 Node.js，您就可以使用 NPM 安装 Bower。使用 Bower，可以更新所有前端库，而无需手动更新它们。一旦安装了 Node.js，安装 Bower 的命令如下：

```php
**npm install -g bower**

```

然后，您可以执行`bower init`来创建项目上的`bower.json`文件。

`bower.json`文件会让您想起`composer.json`：

```php
    {
      "name": “bower-test”,
      "version": "0.0.0",
      "authors": [
        "Carlos Perez and Pablo Solar"
      ],
      "dependencies": {
        "jquery": "~2.1.4",
        "bootstrap": "~3.3.5"
        "angular": "1.4.7",
        "angular-route": "1.4.7",
      }
    }
```

在上述代码中，您可以看到添加到项目中的依赖项。它们可以被修改，以便像 Composer 一样在您的应用程序上安装这些依赖项。此外，与 Composer 一起使用 Bower 的命令非常相似：

+   **bower install:** 这是为了安装`bower.json`中的所有依赖项

+   **bower update:** 这是为了更新`bower.json`中包含的依赖项

+   **bower install package-name:** 这会在 Bower 上安装一个包

# 部署自动化

在某个时刻，您的应用将被部署到生产环境。如果您的应用很小，只使用了少量容器/服务器，那么一切都会很好，您可以轻松地手动管理所有资源（容器、虚拟机、服务器等）在每次部署时。但是，如果您有数百个资源需要在每次部署时更新，那该怎么办呢？在这种情况下，您需要某种部署机制；即使您有一个小项目和一个容器/服务器，我们也建议自动化您的部署。

使用自动部署流程的主要好处如下列出：

+   **易于维护:** 大多数时候，部署所需的步骤可以存储在文件中，这样您就可以编辑它们。

+   **可重复:** 您可以一遍又一遍地执行部署，每次都会按照相同的步骤进行。

+   **更少出错:** 我们是人类，作为人类，我们在多任务处理时会犯错。

+   **易于跟踪:** 有多种工具可用于记录每次提交发生的一切。这些工具也可以用于创建可以进行部署的用户组。您可以使用的最常见的工具是**Jenkins**、**Ansible Tower**和**Atlassian Bamboo**。

+   **更容易更频繁地发布:** 拥有一个部署流水线将帮助您更快地开发和部署，因为您将不会花时间处理将代码推送到生产环境。

让我们看看一些自动化部署的方法，从最简单的选项开始，逐渐增加复杂性和功能。我们将分析每种方法的优缺点，这样，在本章结束时，您将能够选择适合您项目的完美部署系统。

## 简单的 PHP 脚本

这是您可以自动化部署的最简单方式--您可以向您的代码中添加一个脚本（在公共位置），如下所示：

```php
    <?php
    define('MY_KEY', 'this-is-my-secret-key');
    if ($_SERVER['REQUEST_METHOD'] === 
    'POST' && $_REQUEST['key']  === MY_KEY) {
        echo shell_exec('git fetch && git pull origin master');
    }
```

在上述脚本中，只有在使用正确的密钥到达脚本时，我们才会从主分支中拉取。正如您所看到的，这非常简单，任何知道秘钥的人都可以触发它，例如，通过浏览器。如果您的代码仓库允许设置 webhook，您可以使用它们在每次推送或提交时触发您的脚本。

这是这种部署方法的优点：

+   如果所需工作很小，例如`git pull`，那么创建起来很容易

+   很容易跟踪脚本的更改

+   它很容易被您或任何外部工具触发

以下是这种部署方法的缺点：

+   Web 服务器用户需要能够使用存储库

+   当您需要处理分支或标签时，它会变得更加复杂

+   当您需要部署到多个实例时，它不容易使用，您将需要像 rsync 这样的外部工具

+   不太安全。如果您的密钥被第三方发现，他们可以在您的服务器上部署任何他们想要的东西

在理想的世界中，您对生产的所有提交都将是完美和纯净的，但您知道事实--在将来的某个时候，您将需要回滚所有更改。如果您已经使用了这种部署方法，并且想要创建一个回滚策略，您必须增加您的 PHP 脚本的复杂性，以便它可以管理标签。另一个不推荐的选择是，而不是向您的脚本添加回滚，您可以执行，例如，`git undo`并再次推送所有更改。

## Ansible 和 Ansistrano

**Ansible**是一个 IT 自动化引擎，可用于自动化云配置，管理配置，部署应用程序或编排服务等其他用途。该引擎不使用代理，因此无需额外的安全基础设施，它被设计为通过 SSH 使用。用于描述自动化作业（也称为**playbooks**）的主要语言是 YAML，其语法类似于英语。由于所有 playbooks 都是简单的文本文件，因此可以轻松地将它们存储在存储库中。在 Ansible 中可以找到的一个有趣的功能是其 Galaxy，这是一个可以在 playbooks 中使用的附加组件中心。

### Ansible 要求

Ansible 使用 SSH 协议管理所有主机，您只需要在一台机器上安装此工具--您将用来管理主机群的机器。控制机器的主要要求是 Python 2.6 或 2.7（从 Ansible 2.2 开始支持 Python 3），您可以使用除 Microsoft Windows 之外的任何操作系统。

托管主机的唯一要求是 Python 2.4+，这在大多数类 UNIX 操作系统中默认安装。

### Ansible 安装

假设您的控制机器上有正确的 Python 版本，使用包管理器很容易安装 Ansible。

在 RHEL、CentOS 和类似的 Linux 发行版上执行以下命令来安装 Ansible：

```php
**sudo yum install ansible**

```

Ubuntu 命令如下：

```php
**sudo apt-get install software-properties-common \
&& sudo apt-add-repository ppa:ansible/ansible \
&& sudo apt-get update \
&& sudo apt-get install ansible**

```

FreeBSD 命令如下：

```php
**sudo pkg install ansible**

```

Mac OS 命令如下：

```php
**sudo easy_install pip \
&& sudo pip install ansible**

```

### 什么是 Ansistrano？

**Ansistrano**是一个由`ansistrano.deploy`和`ansistrano.rollback`组成的开源项目，这两个 Ansible Galaxy 角色用于轻松管理您的部署。它被认为是 Capistrano 的 Ansible 端口。

一旦我们在我们的机器上有了 Ansible，使用以下命令很容易安装 Ansistrano 角色：

```php
**ansible-galaxy install carlosbuenosvinos.ansistrano-deploy \ carlosbuenosvinos.ansistrano-rollback**

```

执行此命令后，您将能够在您的 playbooks 中使用 Ansistrano。

### Ansistrano 是如何工作的？

Ansistrano 遵循 Capistrano 流程部署您的应用程序：

1.  **设置阶段**：在此阶段，Ansistrano 创建将容纳应用程序发布的文件夹结构。

1.  **代码更新阶段**：在此阶段，Ansistrano 将您的发布放在您的主机上；它可以使用 rsync、Git 或 SVN 等其他方法。

1.  **符号链接阶段**（见下文）：在部署新发布后，它会更改当前软链接，将可用发布指向新发布位置。

1.  **清理阶段**：在此阶段，Ansistrano 会删除存储在您的主机上的旧发布。您可以通过`ansistrano_keep_releases`参数在您的 playbooks 中配置发布的数量。在以下示例中，您将看到此参数的工作方式

### 提示

使用 Ansistrano，您可以挂钩自定义任务以在每个任务之前和之后执行。

让我们看一个简单的示例来解释它是如何工作的。假设你的应用程序部署到`/var/www/my-application`；在第一次部署后，这个文件夹的内容将类似于以下示例：

```php
**-- /var/www/my-application
 |-- current -> /var/www/my-application/releases/20161208145325
 |-- releases
 |   |-- 20161208145325
 |-- shared**

```

如前面的示例所示，当前的符号链接指向我们在主机上拥有的第一个版本。你的应用程序将始终可在相同路径`/var/www/my-application/current`中使用，因此你可以在任何需要的地方使用这个路径，例如 NGINX 或 PHP-FPM。

随着你的部署继续进行，Ansistrano 将为你处理部署。下一个示例将展示在第二次部署后你的应用程序文件夹将会是什么样子：

```php
**-- /var/www/my-application
 |-- current -> /var/www/my-application/releases/20161208182323
 |-- releases
 |   |-- 20161208145325
 |   |-- 20161208182323
 |-- shared**

```

如前面的示例所示，现在我们的主机上有两个版本，并且符号链接已更新，指向你的代码的新版本。如果你使用 Ansistrano 进行回滚会发生什么？很简单，这个工具将删除你的主机上的最新版本，并更新符号链接。在我们的示例中，你的应用程序文件夹内容将类似于这样：

```php
**-- /var/www/my-application
 |-- current -> /var/www/my-application/releases/20161208145325
 |-- releases
 |   |-- 20161208145325
 |-- shared**

```

### 提示

为了避免问题，如果你尝试回滚并且 Ansistrano 找不到要移动到的先前版本，它将不执行任何操作，保持你的主机没有变化。

### 使用 Ansistrano 进行部署

现在，让我们使用 Ansible 和 Ansistrano 创建一个小型的自动化系统。我们假设你有一个已知且持久的基础架构可用，你将在其中推送你的应用程序或微服务。在你的开发环境中创建一个文件夹，用于存放所有的部署脚本。

在我们的情况下，我们之前在本地环境中创建了三个启用了 SSH 的虚拟机。请注意，我们没有涵盖这些虚拟机的配置，但如果你愿意，你甚至可以使用 Ansible 来为你完成这些配置。

你需要创建的第一件事是一个`hosts`文件。在这个文件中，你可以存储和分组所有的服务器/主机，以便以后在部署中使用它们：

```php
**[servers:children]**
 **production**
 **staging**
 **[production]
192.168.99.200
192.168.99.201

[stageing]
192.168.99.100**

```

在上面的配置中，我们创建了两组主机-`production`和`staging`。在每一个组中，我们有一些可用的主机；在我们的情况下，我们设置了我们本地虚拟机的 IP 地址以进行测试，但如果你愿意，你也可以使用 URI。将主机分组的一个优势是你甚至可以创建更大的组；例如，你可以创建一个由其他组组成的组。例如，我们有一个`servers`组，包含了所有的生产和测试主机。如果你想知道如果你有一个动态环境会发生什么，没问题；Ansible 可以帮你，并提供了多个连接器，你可以使用它们来获取你的动态基础架构，例如来自 AWS 或 Digital Ocean 等。

一旦你的`hosts`文件准备好了，现在是时候创建我们的`deploy.yml`文件了，我们将在其中存储所有我们想要在部署中执行的任务。创建一个包含以下内容的`deploy.yml`文件：

```php
**---
- name: Deploying a specific branch to the servers
 hosts: servers
 vars:
     ansistrano_allow_anonymous_stats: no
     ansistrano_current_dir: "current"
     ansistrano_current_via: "symlink"
     ansistrano_deploy_to: "/var/www/my-application"
     ansistrano_deploy_via: "git"
     ansistrano_keep_releases: 5
     ansistrano_version_dir: "releases"

     ansistrano_git_repo: "git@github.com:myuser/myproject.git"
     ansistrano_git_branch: "{{ GIT_BRANCH|default('master') }}"

 roles:
     - { role: carlosbuenosvinos.ansistrano-deploy }**

```

多亏了 Ansistrano，我们的部署任务非常容易定义，如前面的示例所示。我们所做的是创建一个新任务，它将在标记为 servers 的所有主机上执行，并为 Ansistrano 角色定义一些可用的变量。在这里，我们定义了我们将在每个主机上部署我们的应用程序的位置，我们将使用的部署方法（Git），我们将在主机上保留多少个版本（5），以及我们想要部署的分支。

Ansible 的一个有趣的特性是你可以从命令行传递变量到你的通用部署过程中。这就是我们在下面这行中所做的：

```php
**ansistrano_git_branch: "{{ GIT_BRANCH|default('master') }}"**

```

在这里，我们使用`GIT_BRANCH`变量来定义我们想要部署的分支；如果 Ansible 找不到这个定义的变量，它将使用 master 分支。

你准备好测试我们所做的了吗？打开一个终端，转到存储部署任务的位置。假设你想要将最新版本的代码部署到生产主机上，你可以使用以下命令来完成：

```php
**ansible-playbook deploy.yml --extra-vars "GIT_BRANCH=master" --limit production -i hosts**

```

在上述命令中，我们告诉 Ansible 使用我们的`deploy.yml` playbook，并且我们还定义了我们的`GIT_BRANCH`为 master，以便部署该分支。由于我们在 hosts 文件中有所有的主机，并且我们只想将部署限制在`production`主机上，我们使用`--limit` `production`将执行限制到所需的主机。

现在，想象一下，您已经准备好一个新版本，您的所有代码都已提交并标记为`v1.0.4`标签，您想将此版本推送到您的演示环境。您可以使用一个非常简单的命令来完成：

```php
**ansible-playbook deploy.yml --extra-vars "GIT_BRANCH=v1.0.4" --limit staging -i hosts**

```

正如您所看到的，使用 Ansible/Ansistrano 部署您的应用非常容易，甚至可以更轻松地回滚到先前部署的版本。要管理回滚，您只需要创建一个新的 playbook。创建一个名为`rollback.yml`的文件，内容如下：

```php
**---
- name: Rollback
 hosts: servers
 vars:
     ansistrano_deploy_to: "/var/www/my-application"
     ansistrano_version_dir: "releases"
     ansistrano_current_dir: "current"
 roles:
     - { role: carlosbuenosvinos.ansistrano-rollback }**

```

在上述代码片段中，我们使用了 Ansistrano 回滚角色来回滚到先前部署的版本。如果您的主机中只有一个版本，Ansible 将不会撤消更改，因为这是不可能的。您还记得我们在`deploy.yml`文件中设置的名为`ansistrano_keep_releases`的变量吗？这个变量非常重要，可以知道您的主机上可以执行多少次回滚，因此根据您的需求进行调整。要将生产服务器回滚到先前的版本，您可以使用以下命令：

```php
**ansible-playbook rollback.yml --limit production -i hosts**

```

正如您所看到的，Ansible 是一个非常强大的工具，您可以用它进行部署，但它不仅仅用于部署；您甚至可以用它进行编排，例如。有了充满活力的社区和 RedHat 支持该项目，Ansible 是一个必不可少的工具。

### 提示

Ansible 有一个企业版的 Web 工具，您可以用它来管理所有的 Ansible playbooks。尽管它需要付费订阅，但如果您管理的节点少于十个，您可以免费使用它。

## 其他部署工具

正如您可以想象的，有多种不同的工具可以用来进行部署，我们无法在本书中涵盖所有这些工具。我们想向您展示一个简单的（PHP 脚本）和一个更复杂和强大的（Ansible），但我们不希望您在不了解其他可以使用的工具的情况下完成本章：

+   Chef：这是一个有趣的开源工具，您可以用它来管理基础架构作为代码。

+   Puppet：这是一个开源的配置管理工具，有一个付费的企业版本。

+   Bamboo：这是 Atlassian 的一个持续集成服务器，当然，您需要付费才能使用这个工具。这是您可以与 Atlassian 产品目录结合使用的最完整的工具。

+   Codeship：这是一个云持续部署解决方案，旨在成为一个专注于运行测试和部署应用的端到端解决方案的工具

+   Travis CI：这是一个类似于 Jenkins 用于持续集成的工具；您也可以使用它进行部署。

+   Packer、Nomad 和 Terraform：这些是 HashiCorp 的不同工具，您可以用它们来编写您的基础架构作为代码。

+   Capistrano：这是一个众所周知的远程服务器自动化和部署工具，易于理解和使用。

# 高级部署技术

在前面的部分，我们向您展示了一些部署应用程序的方法。现在，是时候使用一些在大型部署中使用的高级技术来增加复杂性了。

## 使用 Jenkins 进行持续集成

Jenkins 是最知名的持续集成应用程序；作为一个开源项目，它允许您以高度灵活的方式创建自己的流水线。它是用 Java 构建的，因此这是您安装此工具时的主要要求。使用 Jenkins，一切都更容易，甚至安装。例如，您可以只用几个命令启动一个带有最新版本的 Docker 容器：

```php
**docker pull jenkins \
&& docker run -d -p 49001:8080 -t jenkins**

```

上述命令将下载并创建一个带有最新 Jenkins 版本的新容器，准备好使用。

Jenkins 背后的主要思想是工作的概念。工作是一系列可以自动或手动执行的命令或步骤。通过工作和插件的使用（可以从 Web UI 下载），你可以创建自定义的工作流程。例如，你可以创建一个类似下一个的工作流程，它会在提交/推送发生时由你的存储库触发：

1.  一个单元测试插件开始测试你的应用程序。

1.  一旦通过，一个代码嗅探器插件检查你的代码。

1.  如果前面的步骤都没问题，Jenkins 通过 SSH 连接到远程主机。

1.  Jenkins 拉取远程主机中的所有更改。

上面的例子很简单；你可以改进和复杂化这个例子，使用 Ansible playbook 而不是 SSH。

这个应用程序非常灵活，你可以用它来检查主从数据库的复制状态。在我们看来，这个应用程序值得一试，你可以找到适应这个软件的各种任务的例子。

## 蓝绿部署

这种部署技术依赖于拥有基础设施的副本，这样你就可以在当前版本的应用程序旁边安装新版本。在应用程序前面，你有一个路由器或**负载均衡器**（LB），用于将流量重定向到所需的版本。一旦你的新版本准备好，你只需要更改你的路由器/LB，将所有流量重定向到新版本。拥有两套发布版本可以让你灵活地进行回滚，并且可以确保新版本运行良好。参考以下图表：

![蓝绿部署](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_08_01.jpg)

微服务的蓝绿部署

正如你从上面的图像中看到的，蓝绿部署可以在应用程序的任何级别进行。在我们的示例图像中，你可以看到一个微服务正在准备部署一个新版本，但尚未发布，你还可以看到一些微服务发布了他们的最新代码版本，保留了以前的版本以便回滚。

这种技术被大型科技公司广泛使用，没有任何问题；主要的缺点是你需要运行应用程序的资源增加了--更多的资源意味着在基础设施上花更多的钱。如果你想试一试，这种部署中最常用的负载均衡器是**ELB**、**Fabio**和**Traefik**等。

## 金丝雀发布

**金丝雀发布**是一种类似于蓝绿部署的部署技术，只是一次只升级少量主机。一旦你有了你想要的部分主机的发布版本，使用 cookie、lb 或代理，一部分流量被重定向到新版本。

这种技术允许你用一小部分流量测试你的更改；如果应用程序表现如预期，我们继续将更多主机迁移到新版本，直到所有流量都被重定向到你的应用程序的新版本。看一下下面的图表：

![金丝雀发布](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_08_02.jpg)

微服务的金丝雀发布

正如你从上面的图像中看到的，有四个微服务实例；其中三个保留了旧版本的应用程序，只有一个有最新版本。LB 用于在不同版本之间分配流量，将大部分流量发送到**v1.0.0**，只有一小部分流量发送到**v2.0.0**。如果一切正常，下一步将是增加**v2.0.0**实例的数量，减少**v1.0.0**实例的数量，并将更多的流量重定向到新版本。

这种部署技术会给您当前的基础设施增加一些复杂性，但允许您开始使用小部分用户/流量测试您的更改。另一个好处是重复使用您现有的基础设施；您不需要复制一套主机来进行部署。

## 不可变基础设施

如今，技术行业的一个趋势是使用不可变基础设施。当我们说不可变基础设施时，我们的意思是您在开发环境中拥有的内容稍后会在没有任何更改的情况下部署到生产环境中。您可以通过容器化技术和一些工具（如 Packer）实现这一点。

使用 Packer，您可以创建应用程序的映像，然后通过您的基础设施分发这个映像。这种技术的主要好处是您确保您的生产环境的行为与您的开发环境相同。另一个重要的方面是安全性；想象一下您的 NGINX 容器中发生了安全漏洞，通过基础映像更新的新版本将解决问题，并且将在不需要外部干预的情况下与您的应用程序一起传播。

# 备份策略

在任何项目中，备份是避免数据丢失的最重要方式之一。在本章中，我们将学习在应用程序中使用的备份策略。

## 什么是备份？

**备份**是将代码或数据保存在与通常存储代码或数据的地方不同的地方的过程。这个过程可以使用不同的策略来完成，但它们都有相同的目标--不丢失数据，以便将来可以访问。

## 为什么重要？

备份可以出于两个原因而进行。第一个原因是由于黑客攻击、数据损坏或在生产服务器上执行查询时出现任何错误而导致数据丢失。此备份将帮助恢复丢失或损坏的数据。

第二个原因是政策。法律规定必须保存用户数据多年。有时，这个功能是由系统完成的，但备份是存储这些数据的另一种方式。

总之，备份让我们保持冷静。我们确保我们正在正确地做事情，并且在任何灾难发生时，我们有解决方案可以快速修复它们，而且没有（重大的）数据丢失。

## 我们需要备份什么和在哪里备份

如果我们在应用程序中使用一些仓库，比如 Git，这可以是我们的文件备份位置。用户上传的资产或其他文件也应该备份。

查看`.gitignore`文件并确保我们已备份该文件夹中包括的所有文件和文件夹是备份所有必要文件的一个良好做法。

此外，最重要和宝贵的备份是数据库。这应该更频繁地备份。

### 提示

不要将备份存储在应用程序正在运行的相同位置。尝试为备份副本选择不同的位置。

## 备份类型

备份可以是完整的、增量的或差异的。我们将看看它们之间的区别以及它们的工作原理。应用程序通常将不同类型的备份结合在一起：完整备份与增量或差异备份。

### 完整备份

完整备份是基本备份；它包括生成当前应用程序的完整副本。大型应用程序定期使用此选项，而小型应用程序可以每天使用它。

优点如下：

+   完整的应用程序备份在一个文件中

+   它总是生成完整副本

缺点如下：

+   生成它可能需要很长时间

+   备份将需要大量的磁盘空间

请注意，通常最好在备份文件名中包含日期/时间，这样您只需查看文件名就可以知道何时创建的。

### 增量和差异备份

增量备份复制自上次备份以来发生变化的数据。这种备份应该包括`datetime`，以便在下次生成新备份时由备份工具检查。

优点如下：

+   比完整备份更快

+   占用更少的磁盘空间

缺点如下：

+   整个应用程序不会存储在单个生成的备份中

还有另一种类型，称为**差异备份**。这类似于增量备份（复制自上次备份以来发生变化的所有数据）；它在第一次执行后将继续复制自上次完整备份以来的所有修改数据。

因此，它会生成比增量备份更多的数据，但在第一次之后比完整备份少。这种类型介于完整和增量之间。它需要比增量备份更多的空间和时间，但比完整备份少。

## 备份工具

可以找到许多备份工具。在大型项目中最常见的工具是 Bacula。对于小型项目，也有其他类似的工具，比如经常运行的自定义脚本。

### Bacula

**Bacula**是一个备份管理工具。这个应用程序管理和自动化备份任务，非常适合大型应用程序。这个工具设置有点复杂，但一旦准备好，就不需要进行任何其他更改，它将可以正常工作。

Bacula 有三个不同的部分，每个部分都需要安装在不同的软件包中：

+   **管理者**：这个管理所有备份过程

+   **存储**：这是备份存储的地方

+   **文件**：这是我们的应用程序运行的客户端机器

在我们基于微服务的应用程序中，我们将有许多文件（每个微服务一个文件），还可以有许多存储位置（为了备份有不同的位置）和管理者。

这个工具使用守护进程。每个部分都有自己的守护进程，并且每个守护进程都遵循自己的配置文件。配置文件在安装过程中设置，只需要更改一些小的东西，比如远程 IP 地址、证书或计划自动化备份。

Bacula 的安全性非常出色--每个部分（管理者、存储和文件）都有自己的密钥，并且根据连接进行加密。此外，Bacula 允许 TLS 连接以提供更多安全性。

Bacula 允许进行完整、增量或差异备份，并且可以在管理者部分自动化。

### Percona xtrabackup

**XtraBackup**是一个开源工具，可以在不阻塞数据库的情况下对应用程序进行热备份。这可能是这个应用程序最重要的特性。

这个工具允许 MySQL 数据库（如 MariaDB 和 Percona）执行流式传输和压缩，并进行增量备份。

优点如下：

+   快速备份和恢复

+   备份期间无中断的事务处理

+   节省磁盘空间和网络带宽

+   自动备份验证

### 自定义脚本

在生产中使用自定义脚本是创建备份的最快方法。这是一个脚本，当运行时，通过执行`mysqldump`（如果我们使用的是 MySQL 数据库），压缩所需的文件，并将它们放在所需的位置（理想情况下是远程的不同机器）来创建备份。

这些脚本应该由 cronjob 执行，可以设置为每天或每周运行一次。

## 验证备份

作为备份策略的一部分，有技术来验证备份中存储的数据是一个好习惯。如果备份中有错误，就像没有任何备份一样。

为了检查我们的备份是否有效，没有损坏，并且按预期工作，需要经常进行模拟恢复，以避免在将来需要恢复时出现故障。

## 做好末日的准备

没有人想要恢复备份，但是在微服务出现故障或损坏并且我们需要快速反应的情况下，做好准备是必要的。

第一步是知道你的应用程序最近的备份在哪里，以便尽快恢复它。

如果问题与数据库有关，我们必须使应用程序停机，恢复数据库备份，检查其是否正常工作，然后再次使应用程序上线。

如果问题与资产或文件之类的东西有关，可以在不使应用程序停机的情况下进行恢复。

保持冷静并备份你的数据。

# 总结

现在你知道如何将你的应用程序部署到生产环境并自动化部署过程。此外，你还学会了需要部署什么以及可以从任何依赖管理中获取它，如何在必要时进行回滚，以及备份应用程序的不同策略。
