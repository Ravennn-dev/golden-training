<?php

use Tests\TestCase;

class ActivityTest extends TestCase
{
    // Raven
    public function test_example()
    {
        $response = $this->get('/test-example');

        $response->assertJson([
            '+ + + + +',
            '- - - - -',
            '+ + + + +',
            '- - - - -',
            '+ + + + +',
        ]);
    }

    public function test_test1()
    {
        $response = $this->get('/test-1');

        $response->assertJson([]);
    }

    public function test_test2()
    {
        $response = $this->get('/test-2');

        $response->assertJson([]);
    }

    public function test_test3()
    {
        $response = $this->get('/test-3');

        $response->assertJson([]);
    }
}
