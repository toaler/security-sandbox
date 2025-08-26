package com.example;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Nested;
import static org.assertj.core.api.Assertions.*;

/**
 * Test class demonstrating JUnit 5 and AssertJ testing capabilities.
 */
@DisplayName("App Tests")
class AppTest {

    @Test
    @DisplayName("Should create App instance")
    void shouldCreateAppInstance() {
        // Given
        App app = new App();
        
        // Then
        assertThat(app).isNotNull();
        assertThat(app).isInstanceOf(App.class);
    }

    @Nested
    @DisplayName("String Tests")
    class StringTests {
        
        private String testString;
        
        @BeforeEach
        void setUp() {
            testString = "Hello, Security Sandbox!";
        }
        
        @Test
        @DisplayName("Should have correct length")
        void shouldHaveCorrectLength() {
            assertThat(testString)
                .hasSize(24)
                .isNotEmpty()
                .isNotBlank();
        }
        
        @Test
        @DisplayName("Should contain expected words")
        void shouldContainExpectedWords() {
            assertThat(testString)
                .contains("Hello")
                .contains("Security")
                .contains("Sandbox")
                .doesNotContain("Goodbye");
        }
        
        @Test
        @DisplayName("Should start and end correctly")
        void shouldStartAndEndCorrectly() {
            assertThat(testString)
                .startsWith("Hello")
                .endsWith("!")
                .doesNotStartWith("Goodbye")
                .doesNotEndWith("?");
        }
    }

    @Nested
    @DisplayName("Number Tests")
    class NumberTests {
        
        @Test
        @DisplayName("Should perform mathematical operations")
        void shouldPerformMathematicalOperations() {
            int a = 10;
            int b = 5;
            
            assertThat(a + b).isEqualTo(15);
            assertThat(a - b).isEqualTo(5);
            assertThat(a * b).isEqualTo(50);
            assertThat(a / b).isEqualTo(2);
        }
        
        @Test
        @DisplayName("Should handle comparisons")
        void shouldHandleComparisons() {
            int small = 5;
            int medium = 10;
            int large = 15;
            
            assertThat(small).isLessThan(medium);
            assertThat(medium).isBetween(small, large);
            assertThat(large).isGreaterThan(medium);
            assertThat(small).isPositive();
            assertThat(0).isZero();
        }
    }

    @Nested
    @DisplayName("Collection Tests")
    class CollectionTests {
        
        @Test
        @DisplayName("Should work with arrays")
        void shouldWorkWithArrays() {
            String[] fruits = {"apple", "banana", "cherry"};
            
            assertThat(fruits)
                .hasSize(3)
                .contains("banana")
                .containsExactly("apple", "banana", "cherry")
                .doesNotContain("orange");
        }
        
        @Test
        @DisplayName("Should work with lists")
        void shouldWorkWithLists() {
            var numbers = java.util.List.of(1, 2, 3, 4, 5);
            
            assertThat(numbers)
                .hasSize(5)
                .contains(3)
                .containsExactly(1, 2, 3, 4, 5)
                .allMatch(n -> n > 0)
                .anyMatch(n -> n == 3)
                .noneMatch(n -> n > 10);
        }
    }

    @Nested
    @DisplayName("Exception Tests")
    class ExceptionTests {
        
        @Test
        @DisplayName("Should throw exception when dividing by zero")
        void shouldThrowExceptionWhenDividingByZero() {
            assertThatThrownBy(() -> {
                int result = 10 / 0;
            })
            .isInstanceOf(ArithmeticException.class)
            .hasMessage("/ by zero");
        }
        
        @Test
        @DisplayName("Should not throw exception for valid operation")
        void shouldNotThrowExceptionForValidOperation() {
            assertThatCode(() -> {
                int result = 10 / 2;
                assertThat(result).isEqualTo(5);
            }).doesNotThrowAnyException();
        }
    }
}
