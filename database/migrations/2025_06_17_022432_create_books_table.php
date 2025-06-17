<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('books', function (Blueprint $table) {
            $table->id('idbooks'); // Primary key
            $table->string('title');
            $table->string('author_name');
            $table->string('isbn')->unique()->nullable();
            $table->text('description')->nullable();
            $table->decimal('price', 8, 2); // Example: 999999.99
            $table->string('currency', 3)->default('USD');
            $table->date('publication_date')->nullable();
            $table->string('cover_image_url')->nullable();
            $table->unsignedInteger('stock_quantity')->default(0);
            $table->enum('status', ['draft', 'available', 'out_of_stock', 'discontinued'])->default('draft');
            $table->uuid('user_id'); // Foreign key for the seller/publisher (User)
            $table->timestamps(); // created_at and updated_at

            $table->foreign('user_id')->references('iduser')->on('users')->onDelete('cascade');
            $table->index('user_id');
            $table->index('status');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('books');
    }
};
