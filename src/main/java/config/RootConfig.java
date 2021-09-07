package config;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.session.SqlSessionFactory;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

import javax.sql.DataSource;

@Configuration
@PropertySource( value = "properties/${spring.profiles.active}.properties", ignoreResourceNotFound = true)
@ComponentScan(basePackages = {"service"})
@MapperScan(basePackages = {"mapper"})
@Slf4j
public class RootConfig {
    @Value("${db.jdbcurl}")             private String jdbcUrl;
    @Value("${db.driverclassname}")     private String driverClassName;
    @Value("${db.username}")            private String username;
    @Value("${db.password}")            private String password;

    private String url = "jdbc:log4jdbc:oracle:thin:@localhost:1521:XE";
    private String driver = "net.sf.log4jdbc.sql.jdbcapi.DriverSpy";
    private String user = "spring_sample";
    private String passwd = "spring_sample";

    @Bean
    public DataSource dataSource() {
        HikariConfig hikariConfig = new HikariConfig();
        hikariConfig.setJdbcUrl(url);
        hikariConfig.setDriverClassName(driver);
        hikariConfig.setUsername(user);
        hikariConfig.setPassword(passwd);
        hikariConfig.setAutoCommit(true);
        return new HikariDataSource(hikariConfig);
    }

    @Bean
    public SqlSessionFactory sqlSessionFactory() throws Exception {
        SqlSessionFactoryBean sqlSessionFactory = new SqlSessionFactoryBean();
        sqlSessionFactory.setDataSource(dataSource());
        return (SqlSessionFactory) sqlSessionFactory.getObject();
    }


}