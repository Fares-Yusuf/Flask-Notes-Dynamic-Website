from website import create_app

app = create_app()
print("Hello World!")
if __name__ == '__main__':
    app.run(debug=True)
