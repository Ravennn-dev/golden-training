<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    @vite(['resources/css/app.css', 'resources/js/app.js'])

    <title>CRUD sample -raven</title>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/sweetalert/2.1.2/sweetalert.min.js"></script>

</head>

<body class="flex justify-center items-center h-screen m-0 bg-[#27548A] font-sans">

    <div class="border-2 p-8 bg-white rounded-xl text-center shadow-inner w-full max-w-sm">
        <h2 class="mb-5 text-4xl font-bold">REGISTER</h2>
        <form id="register-form">
            @csrf
            <input name="name" type="text" placeholder="Name" required
                class="w-[95%] py-2 px-2 mb-2.5 mt-1 rounded-[10px] border border-gray-300 bg-gray-100" />
            <input name="username" type="text" placeholder="Username" required
                class="w-[95%] py-2 px-2 mb-2.5 mt-1 rounded-[10px] border border-gray-300 bg-gray-100" />
            <input name="password" type="password" placeholder="Password" required
                class="w-[95%] py-2 px-2 mb-2.5 mt-1 rounded-[10px] border border-gray-300 bg-gray-100" />
            <button type="submit"
                class="px-5 py-2 mt-4 w-[100px] text-base bg-gray-800 text-white rounded-xl hover:bg-[#27548A] cursor-pointer shadow-md">
                Register
            </button>
        </form>
        <button onclick="window.location.href = '/login'"
            class="px-5 py-2 w-[100px] text-base bg-gray-800 text-white rounded-xl hover:bg-[#27548A] mt-4 cursor-pointer shadow-md">
            Login
        </button>
    </div>

    <script>
    document.getElementById('register-form').addEventListener('submit', function(e) {
        e.preventDefault();
        const formData = new FormData(this);

        fetch('/api/apiRegister', {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').getAttribute(
                        'content')
                },
                body: formData
            })
            .then(res => res.json())
            .then(data => {
                if (data.user) {
                    swal("Success!", data.message, "success")
                        .then(() => window.location.href = '/login');
                } else {
                    swal("Error!", data.message || "Registration failed", "error");
                }
            })
            .catch(() => {
                swal("Error!", "Something went wrong", "error");
            });
    });
    </script>

</body>

</html>