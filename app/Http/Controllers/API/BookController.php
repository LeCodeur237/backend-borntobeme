<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\Book;
use App\Models\User; // For type hinting Auth user
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
use OpenApi\Annotations as OA;

class BookController extends Controller
{
    /**
     * @OA\Get(
     *      path="/books",
     *      operationId="getBooksList",
     *      tags={"Books"},
     *      summary="Get list of books",
     *      description="Returns a paginated list of books. Can be filtered by status, author, title, or price range.",
     *      @OA\Parameter(name="page", in="query", description="Page number", required=false, @OA\Schema(type="integer")),
     *      @OA\Parameter(name="status", in="query", description="Filter by book status", required=false, @OA\Schema(type="string", enum={"draft", "available", "out_of_stock", "discontinued"})),
     *      @OA\Parameter(name="author_name", in="query", description="Filter by author's name (partial match)", required=false, @OA\Schema(type="string")),
     *      @OA\Parameter(name="title", in="query", description="Filter by book title (partial match)", required=false, @OA\Schema(type="string")),
     *      @OA\Parameter(name="min_price", in="query", description="Minimum price", required=false, @OA\Schema(type="number", format="float")),
     *      @OA\Parameter(name="max_price", in="query", description="Maximum price", required=false, @OA\Schema(type="number", format="float")),
     *      @OA\Response(
     *          response=200,
     *          description="Successful operation",
     *          @OA\JsonContent(
     *              type="object",
     *              @OA\Property(property="current_page", type="integer"),
     *              @OA\Property(property="data", type="array", @OA\Items(ref="#/components/schemas/Book")),
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
        $query = Book::with('seller'); // Eager load the seller relationship

        if ($request->has('status')) {
            $query->where('status', $request->input('status'));
        }
        if ($request->has('author_name')) {
            $query->where('author_name', 'like', '%' . $request->input('author_name') . '%');
        }
        if ($request->has('title')) {
            $query->where('title', 'like', '%' . $request->input('title') . '%');
        }
        if ($request->has('min_price')) {
            $query->where('price', '>=', $request->input('min_price'));
        }
        if ($request->has('max_price')) {
            $query->where('price', '<=', $request->input('max_price'));
        }

        $books = $query->orderBy('created_at', 'desc')->paginate(15);
        return response()->json($books);
    }

    /**
     * @OA\Post(
     *      path="/books",
     *      operationId="storeBook",
     *      tags={"Books"},
     *      summary="Create a new book listing",
     *      description="Creates a new book. The authenticated user will be set as the seller.",
     *      security={{"bearerAuth":{}}},
     *      @OA\RequestBody(
     *          required=true,
     *          description="Book data to create",
     *          @OA\JsonContent(ref="#/components/schemas/BookInput")
     *      ),
     *      @OA\Response(
     *          response=201,
     *          description="Book created successfully",
     *          @OA\JsonContent(ref="#/components/schemas/Book")
     *      ),
     *      @OA\Response(response=401, description="Unauthenticated"),
     *      @OA\Response(response=422, description="Validation Error", @OA\JsonContent(ref="#/components/schemas/ValidationError"))
     * )
     */
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'title' => 'required|string|max:255',
            'author_name' => 'required|string|max:255',
            'isbn' => 'nullable|string|max:20|unique:books,isbn',
            'description' => 'nullable|string',
            'price' => 'required|numeric|min:0',
            'currency' => 'nullable|string|max:3',
            'publication_date' => 'nullable|date',
            'cover_image_url' => 'nullable|url|max:255',
            'stock_quantity' => 'nullable|integer|min:0',
            'status' => ['nullable', 'string', Rule::in([Book::STATUS_DRAFT, Book::STATUS_AVAILABLE, Book::STATUS_OUT_OF_STOCK, Book::STATUS_DISCONTINUED])],
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $validatedData = $validator->validated();
        $validatedData['user_id'] = Auth::id(); // Associate with the authenticated user (seller)

        // Set defaults if not provided
        $validatedData['currency'] = $validatedData['currency'] ?? 'USD';
        $validatedData['stock_quantity'] = $validatedData['stock_quantity'] ?? 0;
        $validatedData['status'] = $validatedData['status'] ?? Book::STATUS_DRAFT;


        $book = Book::create($validatedData);
        $book->load('seller'); // Eager load seller information

        return response()->json($book, 201);
    }

    /**
     * @OA\Get(
     *      path="/books/{book_id}",
     *      operationId="getBookById",
     *      tags={"Books"},
     *      summary="Get book information",
     *      description="Returns a single book by its ID.",
     *      @OA\Parameter(
     *          name="book_id",
     *          in="path",
     *          description="ID of book to return",
     *          required=true,
     *          @OA\Schema(type="integer", format="int64")
     *      ),
     *      @OA\Response(response=200, description="Successful operation", @OA\JsonContent(ref="#/components/schemas/Book")),
     *      @OA\Response(response=404, description="Book not found")
     * )
     */
    public function show(int $idbooks)
    {
        $book = Book::with('seller')->findOrFail($idbooks);
        return response()->json($book);
    }

    /**
     * @OA\Put(
     *      path="/books/{book_id}",
     *      operationId="updateBook",
     *      tags={"Books"},
     *      summary="Update an existing book listing",
     *      description="Updates an existing book. Only the seller or an admin can perform this action.",
     *      security={{"bearerAuth":{}}},
     *      @OA\Parameter(
     *          name="book_id",
     *          in="path",
     *          description="ID of book to update",
     *          required=true,
     *          @OA\Schema(type="integer", format="int64")
     *      ),
     *      @OA\RequestBody(
     *          required=true,
     *          description="Book data to update",
     *          @OA\JsonContent(ref="#/components/schemas/BookInput")
     *      ),
     *      @OA\Response(response=200, description="Book updated successfully", @OA\JsonContent(ref="#/components/schemas/Book")),
     *      @OA\Response(response=401, description="Unauthenticated"),
     *      @OA\Response(response=403, description="Forbidden - Not authorized to update this book"),
     *      @OA\Response(response=404, description="Book not found"),
     *      @OA\Response(response=422, description="Validation Error", @OA\JsonContent(ref="#/components/schemas/ValidationError"))
     * )
     */
    public function update(Request $request, int $idbooks)
    {
        $book = Book::findOrFail($idbooks);
        /** @var User $user */
        $user = Auth::user();

        // Authorization check
        if ($user->iduser !== $book->user_id && $user->role !== 'admin') {
            return response()->json(['message' => 'Forbidden. You are not authorized to update this book.'], 403);
        }

        $validator = Validator::make($request->all(), [
            'title' => 'sometimes|required|string|max:255',
            'author_name' => 'sometimes|required|string|max:255',
            'isbn' => ['sometimes', 'nullable', 'string', 'max:20', Rule::unique('books', 'isbn')->ignore($book->idbooks, 'idbooks')],
            'description' => 'sometimes|nullable|string',
            'price' => 'sometimes|required|numeric|min:0',
            'currency' => 'sometimes|nullable|string|max:3',
            'publication_date' => 'sometimes|nullable|date',
            'cover_image_url' => 'sometimes|nullable|url|max:255',
            'stock_quantity' => 'sometimes|nullable|integer|min:0',
            'status' => ['sometimes', 'required', 'string', Rule::in([Book::STATUS_DRAFT, Book::STATUS_AVAILABLE, Book::STATUS_OUT_OF_STOCK, Book::STATUS_DISCONTINUED])],
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $book->update($validator->validated());
        $book->load('seller'); // Eager load seller information

        return response()->json($book);
    }

    /**
     * @OA\Delete(
     *      path="/books/{book_id}",
     *      operationId="deleteBook",
     *      tags={"Books"},
     *      summary="Delete a book listing",
     *      description="Deletes an existing book. Only the seller or an admin can perform this action.",
     *      security={{"bearerAuth":{}}},
     *      @OA\Parameter(
     *          name="book_id",
     *          in="path",
     *          description="ID of book to delete",
     *          required=true,
     *          @OA\Schema(type="integer", format="int64")
     *      ),
     *      @OA\Response(
     *          response=200,
     *          description="Book deleted successfully",
     *          @OA\JsonContent(@OA\Property(property="message", type="string", example="Book deleted successfully"))
     *      ),
     *      @OA\Response(response=401, description="Unauthenticated"),
     *      @OA\Response(response=403, description="Forbidden - Not authorized to delete this book"),
     *      @OA\Response(response=404, description="Book not found")
     * )
     */
    public function destroy(int $idbooks)
    {
        $book = Book::findOrFail($idbooks);
        /** @var User $user */
        $user = Auth::user();

        // Authorization check
        if ($user->iduser !== $book->user_id && $user->role !== 'admin') {
            return response()->json(['message' => 'Forbidden. You are not authorized to delete this book.'], 403);
        }

        $book->delete();

        return response()->json(['message' => 'Book deleted successfully']);
    }
}
