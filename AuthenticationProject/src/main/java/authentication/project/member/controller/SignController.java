package authentication.project.member.controller;

import authentication.project.member.dto.SignRequestDto;
import authentication.project.member.dto.SignResponseDto;
import authentication.project.member.service.SignService;
import authentication.project.security.dto.TokenDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class SignController {
    private final SignService memberService;

    @PostMapping("/register")
    public ResponseEntity<Boolean> signUp(@RequestBody SignRequestDto request) throws Exception{
        return new ResponseEntity<>(memberService.registerByRole(request, "USER"), HttpStatus.OK);
    }

    // 관리자 생성 및 처리 테스트
    @PostMapping("/register/adm")
    public ResponseEntity<Boolean> signUpAdmin(@RequestBody SignRequestDto request) throws Exception{
        return new ResponseEntity<>(memberService.registerByRole(request, "ADMIN"), HttpStatus.OK);
    }

//    @PostMapping("/login")
//    public ResponseEntity<SignResponseDto> login(@RequestBody SignRequestDto request) throws Exception{
//        return new ResponseEntity<>(memberService.login(request), HttpStatus.OK);
//    }

    @GetMapping("/refresh")
    public ResponseEntity<TokenDto> refresh(@RequestBody TokenDto token) throws Exception{
        return new ResponseEntity<>(memberService.refreshAccessToken(token), HttpStatus.OK);
    }

    @GetMapping("/user/get")
    public ResponseEntity<SignResponseDto> getUser(@RequestParam String username) throws Exception{
        return new ResponseEntity<>(memberService.getMember(username), HttpStatus.OK);
    }

    @GetMapping("/admin/get")
    public ResponseEntity<SignResponseDto> getAdmin(@RequestParam String username) throws Exception{
        return new ResponseEntity<>(memberService.getMember(username), HttpStatus.OK);
    }


}
