<?php

use Tests\TestCase;

class ActivityTest extends TestCase
{
    public function test_test1()
    {
        $response = $this->get('/test-1');

        $response->assertJson(['test1']);
    }

    public function test_test2()
    {
        $response = $this->get('/test-2');

        $response->assertJson(['test2']);
    }

    public function test_test3()
    {
        $response = $this->get('/test-3');

        $response->assertJson(['test3']);
    }
}
