package me.bechberger.trace;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BasicTest {

    @Test
    void testPushAndPop() {
        Stack.push("A", "B", "C");
        Stack ts = Stack.get();
        assertEquals(1, ts.length);
        assertEquals("A", ts.classes[0]);
        assertEquals("B", ts.methods[0]);
        assertEquals("C", ts.signatures[0]);
        Stack.pop();
        assertEquals(0, Stack.get().length);
    }
}