# Blog App using spring boot

## Backend setup

### project setup
Initialise project using [Spring Initializer](https://start.spring.io/)
![](./Screenshots/spring_strater.png)

Added below dependecies for field validateion
```
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>
```
add below content to application.properties file
```
## Spring Datasource Configuration
spring.datasource.url=jdbc:mysql://localhost:3306/springblog?useSSL=false&serverTimezone=UTC&useLegacyDatetimeCode=false
spring.datasource.username=root
spring.datasource.password=mysql

## JPA Hibernate Properties
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.MySQL5InnoDBDialect
spring.jpa.hibernate.ddl-auto=update

```
### [Getting Started]

create below package and respective file
1. model
   1. User.java
   2. Post.java
2. dto
   1. RegisterRequest.java
3. repository
   1. PostRepository.java
   2. UserRepository.java
4. service
   1. AuthService.java
5. controller
   1. AuthController.java
6. config
   1. SecurityConfig.java

