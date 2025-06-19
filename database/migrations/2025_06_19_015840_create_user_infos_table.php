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
        Schema::create('user_infos', function (Blueprint $table) {
            $table->id(); // Auto-incrementing primary key for UserInfo itself
            $table->uuid('user_id')->unique(); // Foreign key to users table, unique for one-to-one
            $table->text('bio')->nullable();
            $table->json('preferences')->nullable(); // For storing various user preferences
            $table->timestamps();

            $table->foreign('user_id')
                  ->references('iduser')
                  ->on('users')
                  ->onDelete('cascade');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('user_infos');
    }
};
