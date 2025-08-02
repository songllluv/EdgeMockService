export default {
  async fetch(request) {
    return new Response('Hello, world!', {
        headers: {
            'Content-Type': 'text/plain',
            'Cache-Control': 'no-cache',
        },
        });
  }
}