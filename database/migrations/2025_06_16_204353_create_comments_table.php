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
        Schema::create('comments', function (Blueprint $table) {
            $table->id(); // Primary key, auto-incrementing
            $table->text('content');
            $table->uuid('user_id'); // Foreign key for the user who wrote the comment
            $table->unsignedBigInteger('article_id'); // Foreign key for the article being commented on
            $table->unsignedBigInteger('parent_id')->nullable(); // Foreign key for the parent comment (if it's a reply)
            $table->timestamps(); // created_at and updated_at

            // Foreign key constraints
            $table->foreign('user_id')->references('iduser')->on('users')->onDelete('cascade');
            $table->foreign('article_id')->references('idarticles')->on('articles')->onDelete('cascade');
            $table->foreign('parent_id')->references('id')->on('comments')->onDelete('cascade'); // Or onDelete('set null')

            // Indexes for better query performance
            $table->index('user_id');
            $table->index('article_id');
            $table->index('parent_id');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('comments');
    }
};
