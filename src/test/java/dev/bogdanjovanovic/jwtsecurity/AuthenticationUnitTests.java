package dev.bogdanjovanovic.jwtsecurity;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("Integration tests for Authentication API endpoints")
@Tag("integration")
class AuthenticationUnitTests {

	@Autowired
	private MockMvc mvc;

	@Test
	public void whenUnauthenticatedThen401() throws Exception {
		mvc.perform(get("/api/v1/demo"))
				.andExpect(status().isUnauthorized());
	}

}
