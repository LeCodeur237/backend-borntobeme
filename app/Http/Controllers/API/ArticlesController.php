<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Article;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\Storage; // Import Storage facade
use Mews\Purifier\Facades\Purifier; // Assuming you have mews/purifier installed
use OpenApi\Annotations as OA;

class ArticlesController extends Controller
{
    /**
     * @OA\Get(
     *      path="/articles",
     *      operationId="getArticlesList",
     *      tags={"Articles"},
     *      summary="Get list of articles",
     *      description="Returns a paginated list of articles. Can be filtered by status or category.",
     *      @OA\Parameter(name="page", in="query", description="Page number", required=false, @OA\Schema(type="integer")),
     *      @OA\Parameter(name="status", in="query", description="Filter by article status (draft, published, archived)", required=false, @OA\Schema(type="string", enum={"draft", "published", "archived"})),
     *      @OA\Parameter(name="per_page", in="query", description="Number of articles per page", required=false, @OA\Schema(type="integer", default=15)),
     *      @OA\Parameter(name="category", in="query", description="Filter by article category", required=false, @OA\Schema(type="string")),
     *      @OA\Response(
     *          response=200,
     *          description="Successful operation",
     *          @OA\JsonContent(
     *              type="object",
     *              @OA\Property(property="current_page", type="integer"),
     *              @OA\Property(property="data", type="array", @OA\Items(ref="#/components/schemas/Article")),
     *              @OA\Property(property="first_page_url", type="string", format="url"),
     *              @OA\Property(property="from", type="integer"),
     *              @OA\Property(property="last_page", type="integer"),
     *              @OA\Property(property="last_page_url", type="string", format="url"),
     *              @OA\Property(property="links", type="array", @OA\Items(type="object")),
     *              @OA\Property(property="next_page_url", type="string", format="url", nullable=true),
     *              @OA\Property(property="path", type="string", format="url"),
     *              @OA\Property(property="per_page", type="integer"),
     *              @OA\Property(property="prev_page_url", type="string", format="url", nullable=true),
     *              @OA\Property(property="to", type="integer"),
     *              @OA\Property(property="total", type="integer")
     *          )
     *      )
     * )
     */
    public function index(Request $request)
    {
        $perPage = $request->input('per_page', 15); // Default to 15 if not provided
        $query = Article::with('author');

        if ($request->has('status')) {
            $query->where('status', $request->input('status'));
        }

        if ($request->has('category')) {
            $query->where('category', $request->input('category'));
        }

        $articles = $query->orderBy('created_at', 'desc')->paginate($perPage);
        return response()->json($articles);
    }

    /**
     * @OA\Post(
     *      path="/articles",
     *      operationId="storeArticle",
     *      tags={"Articles"},
     *      summary="Create a new article",
     *      description="Creates a new article. The authenticated user will be set as the author.",
     *      security={{"bearerAuth":{}}},
     *      @OA\RequestBody(
     *          required=true,
     *          description="Article data to create",
     *          @OA\JsonContent(ref="#/components/schemas/ArticleInput")
     *      ),
     *      @OA\Response(
     *          response=201,
     *          description="Article created successfully",
     *          @OA\JsonContent(ref="#/components/schemas/Article")
     *      ),
     *      @OA\Response(response=401, description="Unauthenticated"),
     *      @OA\Response(response=422, description="Validation Error", @OA\JsonContent(ref="#/components/schemas/ValidationError"))
     * )
     */
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'title' => 'required|string|max:255',
            'category' => 'required|string|max:255',
            'description' => 'nullable|string|max:500', // Added description validation
            'content' => 'required|string',
            'link_picture' => 'nullable|image|mimes:jpeg,png,jpg,gif,svg|max:2048', // Validate as an image
            'status' => ['nullable', 'string', Rule::in(['draft', 'published', 'archived'])],
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $validatedData = $validator->validated();
        $validatedData['user_id'] = Auth::id(); // Associate with the authenticated user

        // Sanitize HTML content from Quill editor (if applicable)
        if (isset($validatedData['content'])) {
            $validatedData['content'] = Purifier::clean($validatedData['content']);
        }
        // Handle file upload for link_picture
        if ($request->hasFile('link_picture')) {
            $path = $request->file('link_picture')->store('articles', 'public');
            $validatedData['link_picture'] = Storage::url($path);
        }else{
            $validatedData['link_picture'] = null;
            return response()->json(['errors' => "link picture is empty"], 402);
        }


        // If status is not provided, it will use the DB default 'draft'
        // or you can set it explicitly here if needed.
        // if (!isset($validatedData['status'])) {
        //     $validatedData['status'] = 'draft';
        // }

        $article = Article::create($validatedData);
        $article->load('author'); // Eager load author information

        return response()->json($article, 201);
    }

    /**
     * @OA\Get(
     *      path="/articles/{article_id}",
     *      operationId="getArticleById",
     *      tags={"Articles"},
     *      summary="Get article information",
     *      description="Returns a single article by its ID.",
     *      @OA\Parameter(
     *          name="article_id",
     *          in="path",
     *          description="ID of article to return",
     *          required=true,
     *          @OA\Schema(type="integer", format="int64")
     *      ),
     *      @OA\Response(response=200, description="Successful operation", @OA\JsonContent(ref="#/components/schemas/Article")),
     *      @OA\Response(response=404, description="Article not found")
     * )
     */
    public function show(int $id)
    {
        $article = Article::with('author')->findOrFail($id);
        return response()->json($article);
    }

    /**
     * @OA\Put(
     *      path="/articles/{article_id}",
     *      operationId="updateArticle",
     *      tags={"Articles"},
     *      summary="Update an existing article",
     *      description="Updates an existing article. Only the author or an admin can perform this action.",
     *      security={{"bearerAuth":{}}},
     *      @OA\Parameter(
     *          name="article_id",
     *          in="path",
     *          description="ID of article to update",
     *          required=true,
     *          @OA\Schema(type="integer", format="int64")
     *      ),
     *      @OA\RequestBody(
     *          required=true,
     *          description="Article data to update",
     *          @OA\JsonContent(ref="#/components/schemas/ArticleInput")
     *      ),
     *      @OA\Response(response=200, description="Article updated successfully", @OA\JsonContent(ref="#/components/schemas/Article")),
     *      @OA\Response(response=401, description="Unauthenticated"),
     *      @OA\Response(response=403, description="Forbidden - Not authorized to update this article"),
     *      @OA\Response(response=404, description="Article not found"),
     *      @OA\Response(response=422, description="Validation Error", @OA\JsonContent(ref="#/components/schemas/ValidationError"))
     * )
     */
    public function update(Request $request, int $id)
    {
        $article = Article::findOrFail($id);
        $user = Auth::user();

        // Authorization check
        if ($user->iduser !== $article->user_id && $user->role !== 'admin') {
            return response()->json(['message' => 'Forbidden. You are not authorized to update this article.'], 403);
        }

        $validator = Validator::make($request->all(), [
            'title' => 'sometimes|required|string|max:255',
            'category' => 'sometimes|required|string|max:255',
            'description' => 'sometimes|nullable|string|max:500', // Added description validation
            'content' => 'sometimes|required|string',
            'link_picture' => 'nullable|image|mimes:jpeg,png,jpg,gif,svg|max:2048', // Validate as an image
            'status' => ['sometimes', 'required', 'string', Rule::in(['draft', 'published', 'archived'])],
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $validatedData = $validator->validated();

        // Sanitize HTML content from Quill editor if it's being updated
        if (isset($validatedData['content'])) {
            $validatedData['content'] = Purifier::clean($validatedData['content']);
        }

        // Handle file upload for link_picture during update
        if ($request->hasFile('link_picture')) {
            // Optionally, delete the old image if it exists
            if ($article->link_picture) {
                if (str_starts_with($article->link_picture, url('/storage'))) {
                    $oldPath = substr($article->link_picture, strlen(url('/storage/')));
                    Storage::disk('public')->delete($oldPath);
                }
            }
            $path = $request->file('link_picture')->store('articles', 'public');
            $validatedData['link_picture'] = Storage::url($path);
        }
        $article->update($validatedData);
        $article->load('author'); // Eager load author information

        return response()->json($article);
    }

    /**
     * @OA\Delete(
     *      path="/articles/{article_id}",
     *      operationId="deleteArticle",
     *      tags={"Articles"},
     *      summary="Delete an article",
     *      description="Deletes an existing article. Only the author or an admin can perform this action.",
     *      security={{"bearerAuth":{}}},
     *      @OA\Parameter(
     *          name="article_id",
     *          in="path",
     *          description="ID of article to delete",
     *          required=true,
     *          @OA\Schema(type="integer", format="int64")
     *      ),
     *      @OA\Response(
     *          response=200,
     *          description="Article deleted successfully",
     *          @OA\JsonContent(@OA\Property(property="message", type="string", example="Article deleted successfully"))
     *      ),
     *      @OA\Response(response=401, description="Unauthenticated"),
     *      @OA\Response(response=403, description="Forbidden - Not authorized to delete this article"),
     *      @OA\Response(response=404, description="Article not found")
     * )
     */
    public function destroy(int $id)
    {
        $article = Article::findOrFail($id);
        $user = Auth::user();

        // Authorization check
        if ($user->iduser !== $article->user_id && $user->role !== 'admin') {
            return response()->json(['message' => 'Forbidden. You are not authorized to delete this article.'], 403);
        }

        // Before deleting the article, you might want to delete related comments if not handled by DB cascade
        // Example: $article->comments()->delete(); (Assuming a 'comments' relationship exists)
        // Your 'comments' table migration already has onDelete('cascade') for 'article_id', so this is handled.

        $article->delete();

        return response()->json(['message' => 'Article deleted successfully']);
    }
}

/**
 * @OA\Schema(
 *   schema="Article",
 *   type="object",
 *   title="Article Model (with Author)",
 *   description="Represents an article in the blog, including author details.",
 *   required={"idarticles", "title", "category", "content", "user_id", "status"},
 *   @OA\Property(property="idarticles", type="integer", format="int64", description="Primary key ID of the article", readOnly=true, example=1),
 *   @OA\Property(property="title", type="string", description="Title of the article", example="Understanding Laravel"),
 *   @OA\Property(property="category", type="string", description="Category of the article", example="PHP Frameworks"),
 *   @OA\Property(property="content", type="string", description="Main content of the article", example="Laravel is a web application framework..."),
 *   @OA\Property(property="user_id", type="string", format="uuid", description="UUID of the author (User)", example="a1b2c3d4-e5f6-7890-1234-567890abcdef"),
 *   @OA\Property(property="link_picture", type="string", format="url", nullable=true, description="URL to the article's main picture", example="http://example.com/laravel.jpg"),
 *   @OA\Property(property="status", type="string", enum={"draft", "published", "archived"}, description="Status of the article", default="draft", example="published"),
 *   @OA\Property(property="created_at", type="string", format="date-time", description="Creation timestamp", readOnly=true, example="2023-02-01T10:00:00Z"),
 *   @OA\Property(property="updated_at", type="string", format="date-time", description="Last update timestamp", readOnly=true, example="2023-02-01T11:00:00Z"),
 *   @OA\Property(property="author", ref="#/components/schemas/User", description="The author of the article", readOnly=true)
 * )
 */

/**
 * @OA\Schema(
 *     schema="ArticleInput",
 *     type="object",
 *     title="Article Input Data",
 *     description="Data required to create or update an article.",
 *     required={"title", "category", "content"},
 *     @OA\Property(property="title", type="string", example="My New Article", description="Title of the article"),
 *     @OA\Property(property="category", type="string", example="Tutorials", description="Category of the article"),
 *     @OA\Property(property="description", type="string", nullable=true, example="A short summary of the new article.", description="Short description of the article"),
 *     @OA\Property(property="content", type="string", example="This is the content of my new article.", description="Main content of the article (can be HTML from Quill)"),
 *     @OA\Property(property="link_picture", type="string", format="binary", nullable=true, description="Image file for the article's main picture"),
 *     @OA\Property(property="status", type="string", enum={"draft", "published", "archived"}, example="draft", default="draft", description="Status of the article (draft, published, archived)")
 * )
 */

/**
 * Note: The @OA\Tag for "Articles" is already defined in your base Controller.php.
 * The @OA\Schema for "User" is defined in User.php.
 * The @OA\Schema for "ValidationError" is defined in Controller.php.
 *
 * The Article schema provided here is slightly enhanced to explicitly show the 'author' property
 * when it's eager-loaded, which is common for API responses.
 * The original Article schema in Article.php can also be used or updated.
 *
 * The ArticleInput schema is also defined here for clarity, matching the one in Article.php.
 * If you prefer to keep all model-related schemas strictly in their model files,
 * ensure the schemas in Article.php are comprehensive for API documentation.
 */
