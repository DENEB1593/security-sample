package security;

import config.RootConfig;
import config.SecurityConfig;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {RootConfig.class, SecurityConfig.class})
@Slf4j
public class PasswordEncoderTests {
    @Setter(onMethod_ = @Autowired)
    private PasswordEncoder passwordEncoder;

    @Test
    public void testEncode() {
        String str = "member";

        String enStr = passwordEncoder.encode(str);

        log.info("encode result: {}", enStr);
    }
}
