const supertest = require("supertest");
var server = supertest.agent("http://localhost:8887");

describe("Unit test for travis", () => {
    it("Should return list of notes", (done) => {
        server
            .get('/notes')
            .expect('Content-type', /json/)
            .expect(200)
            .end((err, res) => {
                done();
            })
    })
})