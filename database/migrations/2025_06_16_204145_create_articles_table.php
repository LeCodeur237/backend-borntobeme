<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('articles', function (Blueprint $table) {
            $table->id('idarticles'); // Primary key, auto-incrementing
            $table->string('title');
            $table->string('category'); // Consider a separate table for categories
            $table->text('content');
            $table->uuid('user_id'); // Foreign key for the author (User)
            $table->string('link_picture')->nullable(); // URL to the article's main picture
            $table->string('status')->default('draft'); // e.g., draft, published, archived
            $table->timestamps(); // created_at and updated_at

            $table->foreign('user_id')->references('iduser')->on('users')->onDelete('cascade');

            $table->index('user_id');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('articles');
    }
};
